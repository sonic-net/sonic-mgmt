#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: topology_layer_2_info
short_description: Information module for Topology Layer
  2
description:
  - Get Topology Layer 2 by id.
  - Returns Layer 2 network topology by specified VLAN
    ID.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  vlanID:
    description:
      - VlanID path parameter. Vlan Name for e.g Vlan1,
        Vlan23 etc.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Topology
      GetTopologyDetails
    description: Complete reference of the GetTopologyDetails
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-topology-details
notes:
  - SDK Method used are
    topology.Topology.get_topology_details,
  - Paths used are
    get /dna/intent/api/v1/topology/l2/{vlanID},
"""

EXAMPLES = r"""
---
- name: Get Topology Layer 2 by id
  cisco.dnac.topology_layer_2_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    vlanID: string
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
        "id": "string",
        "links": [
          {
            "additionalInfo": {},
            "endPortID": "string",
            "endPortIpv4Address": "string",
            "endPortIpv4Mask": "string",
            "endPortName": "string",
            "endPortSpeed": "string",
            "greyOut": true,
            "id": "string",
            "linkStatus": "string",
            "source": "string",
            "startPortID": "string",
            "startPortIpv4Address": "string",
            "startPortIpv4Mask": "string",
            "startPortName": "string",
            "startPortSpeed": "string",
            "tag": "string",
            "target": "string"
          }
        ],
        "nodes": [
          {
            "aclApplied": true,
            "additionalInfo": {},
            "customParam": {
              "id": "string",
              "label": "string",
              "parentNodeId": "string",
              "x": 0,
              "y": 0
            },
            "connectedDeviceId": "string",
            "dataPathId": "string",
            "deviceType": "string",
            "deviceSeries": "string",
            "family": "string",
            "fixed": true,
            "greyOut": true,
            "id": "string",
            "ip": "string",
            "label": "string",
            "networkType": "string",
            "nodeType": "string",
            "order": 0,
            "osType": "string",
            "platformId": "string",
            "role": "string",
            "roleSource": "string",
            "softwareVersion": "string",
            "tags": [
              "string"
            ],
            "upperNode": "string",
            "userId": "string",
            "vlanId": "string",
            "x": 0,
            "y": 0
          }
        ]
      },
      "version": "string"
    }
"""
