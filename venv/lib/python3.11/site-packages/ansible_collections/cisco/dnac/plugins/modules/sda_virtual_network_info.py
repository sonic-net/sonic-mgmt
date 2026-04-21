#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_virtual_network_info
short_description: Information module for Sda Virtual
  Network
description:
  - Get all Sda Virtual Network.
  - Get virtual network VN from SDA Fabric.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  virtualNetworkName:
    description:
      - VirtualNetworkName query parameter.
    type: str
  siteNameHierarchy:
    description:
      - SiteNameHierarchy query parameter.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA GetVNFromSDAFabric
    description: Complete reference of the GetVNFromSDAFabric
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-vn-from-sda-fabric
notes:
  - SDK Method used are
    sda.Sda.get_vn,
  - Paths used are
    get /dna/intent/api/v1/business/sda/virtual-network,
"""

EXAMPLES = r"""
---
- name: Get all Sda Virtual Network
  cisco.dnac.sda_virtual_network_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    virtualNetworkName: string
    siteNameHierarchy: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "siteNameHierarchy": "string",
      "virtualNetworkName": "string",
      "fabricName": "string",
      "isInfraVN": true,
      "isDefaultVN": true,
      "virtualNetworkContextId": "string",
      "virtualNetworkId": "string",
      "status": "string",
      "description": "string",
      "executionId": "string"
    }
"""
