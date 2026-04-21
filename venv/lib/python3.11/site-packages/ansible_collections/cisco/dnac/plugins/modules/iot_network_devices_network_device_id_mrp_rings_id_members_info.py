#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: iot_network_devices_network_device_id_mrp_rings_id_members_info
short_description: Information module for Iot Network
  Devices  Network Device Id Mrp Rings Id Members
description:
  - Get all Iot Network Devices  Network Device Id Mrp
    Rings Id Members. - > This API returns the list
    of MRP ring members for the given fields - networkDeviceId
    Network device ID of the MRP ring member. The networkDeviceId
    is the instanceUuid attribute in the response of
    API - /dna/intent/api/v1/networkDevices and id ID
    of the MRP ring. The id of the configured MRP Ring
    can be retrieved using the API /dna/intent/api/v1/iot/networkDevices/${networkDeviceId}/mrpRings
    .
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
  id:
    description:
      - Id path parameter. ID of the MRP ring.
    type: float
  offset:
    description:
      - Offset query parameter. The first record to
        show for this page; the first record is numbered
        1.
    type: int
  limit:
    description:
      - Limit query parameter. The number of records
        to show for this page.
    type: int
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Industrial
      Configuration RetrievesTheListOfNetworkDevicesPartOfMRPRing
    description: Complete reference of the RetrievesTheListOfNetworkDevicesPartOfMRPRing
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-the-list-of-network-devices-part-of-mrp-ring
notes:
  - SDK Method used are
    industrial_configuration.IndustrialConfiguration.retrieves_the_list_of_network_devices_part_of_m_r_p_ring,
  - Paths used are
    get /dna/intent/api/v1/iot/networkDevices/{networkDeviceId}/mrpRings/{id}/members,
"""

EXAMPLES = r"""
---
- name: Get all Iot Network Devices  Network Device
    Id Mrp Rings Id Members
  cisco.dnac.iot_network_devices__network_device_id_mrp_rings_id_members_info:
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
    networkDeviceId: string
    id: 0
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
            "networkDeviceId": "string",
            "id": 0,
            "deviceName": "string",
            "domainId": "string",
            "portName1": "string",
            "portName2": "string",
            "port1Status": "string",
            "port2Status": "string",
            "operationMode": "string",
            "configurationMode": "string"
          }
        ],
        "version": 0
      }
    ]
"""
