#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_images_validations_count_info
short_description: Information module for Network Device
  Images Validations Count
description:
  - Get all Network Device Images Validations Count.
  - Count the number of network device validations.
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
        ACTIVATION, READINESS_CHECK.
    type: str
  type:
    description:
      - Type query parameter. Type of the validation.
        Available values PRE_VALIDATION, POST_VALIDATION.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Software
      Image Management (SWIM) CountOfCustomNetworkDeviceValidations
    description: Complete reference of the CountOfCustomNetworkDeviceValidations
      API.
    link: https://developer.cisco.com/docs/dna-center/#!count-of-custom-network-device-validations
notes:
  - SDK Method used are
    software_image_management_swim.SoftwareImageManagementSwim.count_of_custom_network_device_validations,
  - Paths used are
    get /dna/intent/api/v1/networkDeviceImages/validations/count,
"""

EXAMPLES = r"""
---
- name: Get all Network Device Images Validations Count
  cisco.dnac.network_device_images_validations_count_info:
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
