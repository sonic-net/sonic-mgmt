#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_images_id_info
short_description: Information module for Network Device
  Images Id
description:
  - Get Network Device Images Id by id. - > The API
    retrieves information about running images and golden
    image bundle, if they are available for the network
    device. It also provides network device update status
    and image update status related to the golden image
    bundle and the compatible features supported by
    the network device. Network device with `networkDeviceImageStatus`
    set as `OUTDATED` is considered ready for update
    based on the golden image bundle.
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
      - Id path parameter. Network device identifier.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Software
      Image Management (SWIM) FetchNetworkDeviceWithImageDetails
    description: Complete reference of the FetchNetworkDeviceWithImageDetails
      API.
    link: https://developer.cisco.com/docs/dna-center/#!fetch-network-device-with-image-details
notes:
  - SDK Method used are
    software_image_management_swim.SoftwareImageManagementSwim.fetch_network_device_with_image_details,
  - Paths used are
    get /dna/intent/api/v1/networkDeviceImages/{id},
"""

EXAMPLES = r"""
---
- name: Get Network Device Images Id by id
  cisco.dnac.network_device_images_id_info:
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
        "managementAddress": "string",
        "networkDevice": {
          "id": "string",
          "productNameOrdinal": 0,
          "productName": "string",
          "supervisorProductName": "string",
          "supervisorProductNameOrdinal": 0
        },
        "networkDeviceImageStatus": "string",
        "networkDeviceUpdateStatus": "string",
        "goldenImages": [
          {
            "id": "string",
            "name": "string",
            "version": "string",
            "imageType": "string",
            "goldenTaggingDetails": {
              "deviceRoles": "string",
              "deviceTags": "string",
              "siteId": "string",
              "siteName": "string",
              "isInherited": true
            }
          }
        ],
        "installedImages": [
          {
            "id": "string",
            "name": "string",
            "version": "string",
            "imageType": "string"
          }
        ],
        "compatibleFeatures": [
          {
            "key": "string",
            "value": "string"
          }
        ]
      },
      "version": "string"
    }
"""
