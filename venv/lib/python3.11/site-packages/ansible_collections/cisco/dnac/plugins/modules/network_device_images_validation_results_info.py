#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_images_validation_results_info
short_description: Information module for Network Device
  Images Validation Results
description:
  - Get all Network Device Images Validation Results.
    - > This API provides a comprehensive overview of
    the outcomes from various tests and assessments
    defined by system and custom validations related
    to network device images. These results are essential
    for identifying potential issues, verifying configurations,
    and ensuring that the network meets the requirement
    for image update.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  networkDeviceId:
    description:
      - NetworkDeviceId query parameter. Network device
        identifier.
    type: str
  id:
    description:
      - Id query parameter. Unique identifier of network
        device validation task.
    type: str
  operationType:
    description:
      - >
        OperationType query parameter. The operation
        type, as part of which this validation will
        get triggered. Available values DISTRIBUTION,
        ACTIVATION, READINESS_CHECK.
    type: str
  status:
    description:
      - Status query parameter. Status of the validation
        result. SUCCESS, FAILED, IN_PROGRESS, WARNING.
    type: str
  type:
    description:
      - Type query parameter. Type of the validation.
        Available values PRE_VALIDATION, POST_VALIDATION.
    type: str
  sortBy:
    description:
      - SortBy query parameter. A property within the
        response to sort by.
    type: str
  order:
    description:
      - >
        Order query parameter. Whether ascending or
        descending order should be used to sort the
        response. Available values asc, desc.
    type: str
  limit:
    description:
      - >
        Limit query parameter. The number of records
        to show for this page. The minimum and maximum
        values are 1 and 500, respectively.
    type: int
  offset:
    description:
      - >
        Offset query parameter. The first record to
        show for this page; the first record is numbered
        1. The minimum value is 1.
    type: int
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Software
      Image Management (SWIM) NetworkDeviceImageUpdateValidationResults
    description: Complete reference of the NetworkDeviceImageUpdateValidationResults
      API.
    link: https://developer.cisco.com/docs/dna-center/#!network-device-image-update-validation-results
notes:
  - SDK Method used are
    software_image_management_swim.SoftwareImageManagementSwim.network_device_image_update_validation_results,
  - Paths used are
    get /dna/intent/api/v1/networkDeviceImages/validationResults,
"""

EXAMPLES = r"""
---
- name: Get all Network Device Images Validation Results
  cisco.dnac.network_device_images_validation_results_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    networkDeviceId: string
    id: string
    operationType: string
    status: string
    type: string
    sortBy: string
    order: string
    limit: 0
    offset: 0
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
          "parentId": "string",
          "name": "string",
          "operationType": "string",
          "type": "string",
          "networkDeviceId": "string",
          "startTime": 0,
          "endTime": 0,
          "status": "string",
          "resultDetails": {
            "key": "string",
            "value": "string"
          }
        }
      ],
      "version": "string"
    }
"""
