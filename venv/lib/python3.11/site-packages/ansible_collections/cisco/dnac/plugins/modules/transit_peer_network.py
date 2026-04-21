#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: transit_peer_network
short_description: Resource module for Transit Peer
  Network
description:
  - Manage operations create and delete of the resource
    Transit Peer Network.
  - Add Transit Peer Network in SD-Access.
  - Delete Transit Peer Network from SD-Access.
version_added: '6.0.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  ipTransitSettings:
    description: Transit Peer Network's ipTransitSettings.
    suboptions:
      autonomousSystemNumber:
        description: Autonomous System Number.
        type: str
      routingProtocolName:
        description: Routing Protocol Name.
        type: str
    type: dict
  sdaTransitSettings:
    description: Transit Peer Network's sdaTransitSettings.
    suboptions:
      transitControlPlaneSettings:
        description: Transit Peer Network's transitControlPlaneSettings.
        elements: dict
        suboptions:
          deviceManagementIpAddress:
            description: Device Management Ip Address
              of provisioned device.
            type: str
          siteNameHierarchy:
            description: Site Name Hierarchy where device
              is provisioned.
            type: str
        type: list
    type: dict
  transitPeerNetworkName:
    description: TransitPeerNetworkName query parameter.
      Transit Peer Network Name.
    type: str
  transitPeerNetworkType:
    description: Transit Peer Network Type.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA AddTransitPeerNetwork
    description: Complete reference of the AddTransitPeerNetwork
      API.
    link: https://developer.cisco.com/docs/dna-center/#!add-transit-peer-network
  - name: Cisco DNA Center documentation for SDA DeleteTransitPeerNetwork
    description: Complete reference of the DeleteTransitPeerNetwork
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-transit-peer-network
notes:
  - SDK Method used are
    sda.Sda.add_transit_peer_network,
    sda.Sda.delete_transit_peer_network,
  - Paths used are
    post /dna/intent/api/v1/business/sda/transit-peer-network,
    delete /dna/intent/api/v1/business/sda/transit-peer-network,
"""

EXAMPLES = r"""
---
- name: Delete all
  cisco.dnac.transit_peer_network:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    transitPeerNetworkName: string
- name: Create
  cisco.dnac.transit_peer_network:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    ipTransitSettings:
      autonomousSystemNumber: string
      routingProtocolName: string
    sdaTransitSettings:
      transitControlPlaneSettings:
        - deviceManagementIpAddress: string
          siteNameHierarchy: string
    transitPeerNetworkName: string
    transitPeerNetworkType: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "status": "string",
      "description": "string",
      "taskId": "string",
      "taskStatusUrl": "string",
      "executionStatusUrl": "string",
      "executionId": "string"
    }
"""
