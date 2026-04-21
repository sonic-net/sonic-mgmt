#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wireless_controllers_mesh_ap_neighbours_info
short_description: Information module for Wireless Controllers
  Mesh Ap Neighbours
description:
  - Get all Wireless Controllers Mesh Ap Neighbours.
  - Retrieves all Mesh accesspoint Neighbours details
    whether child, parent, etc.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  wlcIpAddress:
    description:
      - >
        WlcIpAddress query parameter. Employ this query
        parameter to obtain the details of the Access
        points corresponding to the provided WLC IP
        address.
    type: str
  apName:
    description:
      - >
        ApName query parameter. Employ this query parameter
        to obtain the details of the Access points corresponding
        to the provided ap name.
    type: str
  ethernetMacAddress:
    description:
      - >
        EthernetMacAddress query parameter. Employ this
        query parameter to obtain the details of the
        Access points corresponding to the provided
        EthernetMacAddress.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      GetMeshApNeighbours
    description: Complete reference of the GetMeshApNeighbours
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-mesh-ap-neighbours
notes:
  - SDK Method used are
    wireless.Wireless.get_mesh_ap_neighbours,
  - Paths used are
    get /dna/intent/api/v1/wirelessControllers/meshApNeighbours,
"""

EXAMPLES = r"""
---
- name: Get all Wireless Controllers Mesh Ap Neighbours
  cisco.dnac.wireless_controllers_mesh_ap_neighbours_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    wlcIpAddress: string
    apName: string
    ethernetMacAddress: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "id": "string",
      "apName": "string",
      "ethernetMacAddress": "string",
      "neighbourMacAddress": "string",
      "wlcIpAddress": "string",
      "neighbourType": "string",
      "meshRole": "string",
      "neighbourApName": "string"
    }
"""
