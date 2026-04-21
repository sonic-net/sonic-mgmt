#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_transit_networks_count_info
short_description: Information module for Sda Transit
  Networks Count
description:
  - Get all Sda Transit Networks Count.
  - Returns the count of transit networks that match
    the provided query parameters.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  type:
    description:
      - >
        Type query parameter. Type of the transit network.
        Allowed values are IP_BASED_TRANSIT, SDA_LISP_PUB_SUB_TRANSIT,
        SDA_LISP_BGP_TRANSIT.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA GetTransitNetworksCount
    description: Complete reference of the GetTransitNetworksCount
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-transit-networks-count
notes:
  - SDK Method used are
    sda.Sda.get_transit_networks_count,
  - Paths used are
    get /dna/intent/api/v1/sda/transitNetworks/count,
"""

EXAMPLES = r"""
---
- name: Get all Sda Transit Networks Count
  cisco.dnac.sda_transit_networks_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    type: string
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
        "count": 0
      },
      "version": "string"
    }
"""
