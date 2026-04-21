#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: business_sda_virtual_network_summary_info
short_description: Information module for Business Sda
  Virtual Network Summary
description:
  - Get all Business Sda Virtual Network Summary.
  - Get Virtual Network Summary.
version_added: '6.0.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  siteNameHierarchy:
    description:
      - SiteNameHierarchy query parameter. Complete
        fabric siteNameHierarchy Path.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA GetVirtualNetworkSummary
    description: Complete reference of the GetVirtualNetworkSummary
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-virtual-network-summary
notes:
  - SDK Method used are
    sda.Sda.get_virtual_network_summary,
  - Paths used are
    get /dna/intent/api/v1/business/sda/virtual-network/summary,
"""

EXAMPLES = r"""
---
- name: Get all Business Sda Virtual Network Summary
  cisco.dnac.business_sda_virtual_network_summary_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
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
      "virtualNetworkCount": 0,
      "virtualNetworkSummary": [
        {
          "virtualNetworkContextId": "string",
          "virtualNetworkId": "string",
          "siteNameHierarchy": "string",
          "virtualNetworkName": "string",
          "layer3Instance": 0,
          "virtualNetworkStatus": "string"
        }
      ],
      "status": "string",
      "description": "string",
      "executionId": "string"
    }
"""
