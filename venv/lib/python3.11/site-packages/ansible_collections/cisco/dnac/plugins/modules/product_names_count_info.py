#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: product_names_count_info
short_description: Information module for Product Names
  Count
description:
  - Get all Product Names Count.
  - Count of product names based on filter criteria.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  productName:
    description:
      - >
        ProductName query parameter. Filter with network
        device product name. Supports partial case-insensitive
        search. A minimum of 3 characters are required
        for search.
    type: str
  productId:
    description:
      - ProductId query parameter. Filter with product
        ID (PID).
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Software
      Image Management (SWIM) CountOfNetworkProductNames
    description: Complete reference of the CountOfNetworkProductNames
      API.
    link: https://developer.cisco.com/docs/dna-center/#!count-of-network-product-names
notes:
  - SDK Method used are
    software_image_management_swim.SoftwareImageManagementSwim.count_of_network_product_names,
  - Paths used are
    get /dna/intent/api/v1/productNames/count,
"""

EXAMPLES = r"""
---
- name: Get all Product Names Count
  cisco.dnac.product_names_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    productName: string
    productId: string
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
