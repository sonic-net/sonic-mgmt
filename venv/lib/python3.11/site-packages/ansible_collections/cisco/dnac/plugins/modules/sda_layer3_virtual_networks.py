#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_layer3_virtual_networks
short_description: Resource module for Sda Layer3virtualnetworks
description:
  - Manage operations create, update and delete of the
    resource Sda Layer3virtualnetworks.
  - Adds layer 3 virtual networks based on user input.
  - Deletes layer 3 virtual networks based on user input.
  - Updates layer 3 virtual networks based on user input.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  payload:
    description: Sda Layer3 Virtual Networks's payload.
    elements: dict
    suboptions:
      anchoredSiteId:
        description: Fabric ID of the fabric site this
          layer 3 virtual network is to be anchored
          at.
        type: str
      fabricIds:
        description: IDs of the fabrics this layer 3
          virtual network is to be assigned to.
        elements: str
        type: list
      virtualNetworkName:
        description: Name of the layer 3 virtual network.
        type: str
    type: list
  virtualNetworkName:
    description: VirtualNetworkName query parameter.
      Name of the layer 3 virtual network.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA AddLayer3VirtualNetworks
    description: Complete reference of the AddLayer3VirtualNetworks
      API.
    link: https://developer.cisco.com/docs/dna-center/#!add-layer-3-virtual-networks
  - name: Cisco DNA Center documentation for SDA DeleteLayer3VirtualNetworks
    description: Complete reference of the DeleteLayer3VirtualNetworks
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-layer-3-virtual-networks
  - name: Cisco DNA Center documentation for SDA UpdateLayer3VirtualNetworks
    description: Complete reference of the UpdateLayer3VirtualNetworks
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-layer-3-virtual-networks
notes:
  - SDK Method used are
    sda.Sda.add_layer3_virtual_networks,
    sda.Sda.delete_layer3_virtual_networks,
    sda.Sda.update_layer3_virtual_networks,
  - Paths used are
    post /dna/intent/api/v1/sda/layer3VirtualNetworks,
    delete /dna/intent/api/v1/sda/layer3VirtualNetworks,
    put /dna/intent/api/v1/sda/layer3VirtualNetworks,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.sda_layer3VirtualNetworks:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:
      - anchoredSiteId: string
        fabricIds:
          - string
        virtualNetworkName: string
- name: Delete all
  cisco.dnac.sda_layer3VirtualNetworks:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    virtualNetworkName: string
- name: Update all
  cisco.dnac.sda_layer3VirtualNetworks:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:
      - anchoredSiteId: string
        fabricIds:
          - string
        id: string
        virtualNetworkName: string
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
