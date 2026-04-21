#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_images_validations_info
short_description: Information module for Network Device
  Images Validations
description:
  - Get all Network Device Images Validations. - > Fetches
    custom network device validations that run on the
    network device as part of the update workflow. This
    process verifies and assesses the configuration
    of the network devices.
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
      - ProductSeriesOrdinal query parameter. Unique
        identifier of product series.
    type: float
  operationType:
    description:
      - >
        OperationType query parameter. The operation
        type, as part of which this validation will
        get triggered. Available values DISTRIBUTION,
        ACTIVATION.
    type: str
  type:
    description:
      - Type query parameter. Type of the validation.
        Available values PRE_VALIDATION, POST_VALIDATION.
    type: str
  order:
    description:
      - >
        Order query parameter. Whether ascending or
        descending order should be used to sort the
        response. Available values asc, desc.
    type: str
  offset:
    description:
      - >
        Offset query parameter. The first record to
        show for this page; the first record is numbered
        1. The minimum value is 1.
    type: int
  limit:
    description:
      - >
        Limit query parameter. The number of records
        to show for this page. The minimum and maximum
        values are 1 and 500, respectively.
    type: int
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Software
      Image Management (SWIM) GetTheListOfCustomNetworkDeviceValidations
    description: Complete reference of the GetTheListOfCustomNetworkDeviceValidations
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-the-list-of-custom-network-device-validations
notes:
  - SDK Method used are
    software_image_management_swim.SoftwareImageManagementSwim.get_the_list_of_custom_network_device_validations,
  - Paths used are
    get /dna/intent/api/v1/networkDeviceImages/validations,
"""

EXAMPLES = r"""
---
- name: Get all Network Device Images Validations
  cisco.dnac.network_device_images_validations_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    productSeriesOrdinal: 0
    operationType: string
    type: string
    order: string
    offset: 0
    limit: 0
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": [
        {
          "id": "string",
          "name": "string",
          "type": "string",
          "operationType": "string",
          "description": "string",
          "category": "string",
          "cli": "string",
          "productSeriesOrdinals": [
            0
          ]
        }
      ],
      "version": "string"
    }
"""
