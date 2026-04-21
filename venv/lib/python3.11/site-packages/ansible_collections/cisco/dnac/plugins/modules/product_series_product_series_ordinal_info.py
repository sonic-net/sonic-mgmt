#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: product_series_product_series_ordinal_info
short_description: Information module for Product Series
  Product Series Ordinal
description:
  - Get Product Series Product Series Ordinal by id.
  - Get the network device product series, its ordinal.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  productSeriesOrdinal:
    description:
      - ProductSeriesOrdinal path parameter. Unique
        identifier of product series.
    type: float
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Software
      Image Management (SWIM) RetrieveNetworkDeviceProductSeries
    description: Complete reference of the RetrieveNetworkDeviceProductSeries
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieve-network-device-product-series
notes:
  - SDK Method used are
    software_image_management_swim.SoftwareImageManagementSwim.retrieve_network_device_product_series,
  - Paths used are
    get /dna/intent/api/v1/productSeries/{productSeriesOrdinal},
"""

EXAMPLES = r"""
---
- name: Get Product Series Product Series Ordinal by
    id
  cisco.dnac.product_series_product_series_ordinal_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    productSeriesOrdinal: 0
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
        "id": "string",
        "productSeries": "string",
        "productNameOrdinal": 0
      },
      "version": "string"
    }
"""
