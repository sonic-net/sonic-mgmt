#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_virtual_network_v2_info
short_description: Information module for Sda Virtual
  Network V2
description:
  - Get all Sda Virtual Network V2.
  - Get virtual network with scalable groups.
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
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA GetVirtualNetworkWithScalableGroups
    description: Complete reference of the GetVirtualNetworkWithScalableGroups
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-virtual-network-with-scalable-groups
notes:
  - SDK Method used are
    sda.Sda.get_virtual_network_with_scalable_groups,
  - Paths used are
    get /dna/intent/api/v1/virtual-network,
"""

EXAMPLES = r"""
---
- name: Get all Sda Virtual Network V2
  cisco.dnac.sda_virtual_network_v2_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    virtualNetworkName: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "virtualNetworkName": "string",
      "isGuestVirtualNetwork": true,
      "scalableGroupNames": [
        "string"
      ],
      "vManageVpnId": "string",
      "virtualNetworkContextId": "string",
      "status": "string",
      "description": "string",
      "executionId": "string"
    }
"""
