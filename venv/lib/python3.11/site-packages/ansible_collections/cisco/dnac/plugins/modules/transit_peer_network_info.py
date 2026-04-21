#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: transit_peer_network_info
short_description: Information module for Transit Peer
  Network
description:
  - Get all Transit Peer Network.
  - Get Transit Peer Network Info from SD-Access.
version_added: '6.0.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  transitPeerNetworkName:
    description:
      - TransitPeerNetworkName query parameter. Transit
        or Peer Network Name.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA GetTransitPeerNetworkInfo
    description: Complete reference of the GetTransitPeerNetworkInfo
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-transit-peer-network-info
notes:
  - SDK Method used are
    sda.Sda.get_transit_peer_network_info,
  - Paths used are
    get /dna/intent/api/v1/business/sda/transit-peer-network,
"""

EXAMPLES = r"""
---
- name: Get all Transit Peer Network
  cisco.dnac.transit_peer_network_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    transitPeerNetworkName: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "transitPeerNetworkName": "string",
      "transitPeerNetworkType": "string",
      "ipTransitSettings": {
        "routingProtocolName": "string",
        "autonomousSystemNumber": "string"
      },
      "sdaTransitSettings": {
        "transitControlPlaneSettings": [
          {
            "siteNameHierarchy": "string",
            "deviceManagementIpAddress": "string"
          }
        ]
      },
      "status": "string",
      "description": "string",
      "transitPeerNetworkId": "string"
    }
"""
