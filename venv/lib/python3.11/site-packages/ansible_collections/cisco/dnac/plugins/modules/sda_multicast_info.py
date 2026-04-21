#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_multicast_info
short_description: Information module for Sda Multicast
description:
  - Get all Sda Multicast.
  - Get multicast details from SDA fabric.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  siteNameHierarchy:
    description:
      - SiteNameHierarchy query parameter. Fabric site
        name hierarchy.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA GetMulticastDetailsFromSDAFabric
    description: Complete reference of the GetMulticastDetailsFromSDAFabric
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-multicast-details-from-sda-fabric
notes:
  - SDK Method used are
    sda.Sda.get_multicast_details_from_sda_fabric,
  - Paths used are
    get /dna/intent/api/v1/business/sda/multicast,
"""

EXAMPLES = r"""
---
- name: Get all Sda Multicast
  cisco.dnac.sda_multicast_info:
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
      "multicastMethod": "string",
      "multicastType": "string",
      "multicastVnInfo": [
        {
          "virtualNetworkName": "string",
          "ipPoolName": "string",
          "internalRpIpAddress": [
            "string"
          ],
          "externalRpIpAddress": "string",
          "ssmInfo": [
            {
              "ssmGroupRange": "string",
              "ssmWildcardMask": "string"
            }
          ]
        }
      ],
      "status": "string",
      "description": "string"
    }
"""
