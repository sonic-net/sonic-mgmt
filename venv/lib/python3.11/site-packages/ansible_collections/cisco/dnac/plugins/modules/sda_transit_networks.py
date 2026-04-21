#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_transit_networks
short_description: Resource module for Sda Transit Networks
description:
  - Manage operations create, update and delete of the
    resource Sda Transit Networks.
  - Adds transit networks based on user input.
  - Updates transit networks based on user input.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  payload:
    description: Sda Transit Networks's payload.
    elements: dict
    suboptions:
      id:
        description: ID of the transit network (updating
          this field is not allowed).
        type: str
      ipTransitSettings:
        description: Sda Transit Networks's ipTransitSettings.
        suboptions:
          autonomousSystemNumber:
            description: Autonomous System Number of
              the IP transit network. Allowed range
              is 1 to 4294967295 (updating this field
              is not allowed).
            type: str
          routingProtocolName:
            description: Routing Protocol Name of the
              IP transit network (updating this field
              is not allowed).
            type: str
        type: dict
      name:
        description: Name of the transit network (updating
          this field is not allowed).
        type: str
      sdaTransitSettings:
        description: Sda Transit Networks's sdaTransitSettings.
        suboptions:
          controlPlaneNetworkDeviceIds:
            description: List of network device IDs
              that will be used as control plane nodes.
              Maximum 2 network device IDs can be provided
              for transit of type SDA_LISP_BGP_TRANSIT
              and maximum 4 network device IDs can be
              provided for transit of type SDA_LISP_PUB_SUB_TRANSIT.
            elements: str
            type: list
          isMulticastOverTransitEnabled:
            description: Set this to true to enable
              multicast over SD-Access transit. This
              supports Native Multicast over SD-Access
              Transit. This is only applicable for transit
              of type SDA_LISP_PUB_SUB_TRANSIT.
            type: bool
        type: dict
      siteId:
        description: ID of the site of this transit
          network. The transit network will be anchored
          at this Site. Only Fabric Sites within this
          Site location can associate their borders
          with this transit network. Additionally, the
          Transit Control Plane Devices must be located
          within the transit network's Site.
        type: str
      type:
        description: Type of the transit network (updating
          this field is not allowed).
        type: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA AddTransitNetworks
    description: Complete reference of the AddTransitNetworks
      API.
    link: https://developer.cisco.com/docs/dna-center/#!add-transit-networks
  - name: Cisco DNA Center documentation for SDA UpdateTransitNetworks
    description: Complete reference of the UpdateTransitNetworks
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-transit-networks
notes:
  - SDK Method used are
    sda.Sda.add_transit_networks,
    sda.Sda.update_transit_networks,
  - Paths used are
    post /dna/intent/api/v1/sda/transitNetworks,
    put /dna/intent/api/v1/sda/transitNetworks,
"""

EXAMPLES = r"""
---
- name: Update all
  cisco.dnac.sda_transit_networks:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:
      - id: string
        ipTransitSettings:
          autonomousSystemNumber: string
          routingProtocolName: string
        name: string
        sdaTransitSettings:
          controlPlaneNetworkDeviceIds:
            - string
          isMulticastOverTransitEnabled: true
        siteId: string
        type: string
- name: Create
  cisco.dnac.sda_transit_networks:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:
      - ipTransitSettings:
          autonomousSystemNumber: string
          routingProtocolName: string
        name: string
        sdaTransitSettings:
          controlPlaneNetworkDeviceIds:
            - string
          isMulticastOverTransitEnabled: true
        siteId: string
        type: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": "string",
        "url": "string"
      },
      "version": "string"
    }
"""
