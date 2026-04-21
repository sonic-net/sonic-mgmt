#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_images_validations_id_info
short_description: Information module for Network Device
  Images Validations Id
description:
  - Get Network Device Images Validations Id by id.
  - This API fetches the details for the given network
    device validation.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  id:
    description:
      - Id path parameter. Unique identifier of network
        device validation.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Software
      Image Management (SWIM) GetCustomNetworkDeviceValidationDetails
    description: Complete reference of the GetCustomNetworkDeviceValidationDetails
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-custom-network-device-validation-details
notes:
  - SDK Method used are
    software_image_management_swim.SoftwareImageManagementSwim.get_custom_network_device_validation_details,
  - Paths used are
    get /dna/intent/api/v1/networkDeviceImages/validations/{id},
"""

EXAMPLES = r"""
---
- name: Get Network Device Images Validations Id by
    id
  cisco.dnac.network_device_images_validations_id_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    id: string
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
        "name": "string",
        "type": "string",
        "operationType": "string",
        "description": "string",
        "category": "string",
        "cli": "string",
        "productSeriesOrdinals": [
          0
        ]
      },
      "version": "string"
    }
"""
