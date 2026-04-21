#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_images_info
short_description: Information module for Network Device
  Images
description:
  - Get all Network Device Images. - > This API retrieves
    information about running images and golden image
    bundle, if they are available for network devices.
    It also provides network device update status and
    image update status related to the golden image
    bundle and the compatible features supported by
    the network devices.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  managementAddress:
    description:
      - ManagementAddress query parameter. IP address
        or DNS name used to access and manage network
        devices.
    type: str
  networkDeviceImageStatus:
    description:
      - >
        NetworkDeviceImageStatus query parameter. Network
        device image status with respect to golden images.
        Available values OUTDATED, UP_TO_DATE, UNKNOWN,
        CONFLICTED, UNSUPPORTED.
    type: str
  networkDeviceUpdateStatus:
    description:
      - >
        NetworkDeviceUpdateStatus query parameter. Network
        device current update status with respect to
        golden images. Available values DISTRIBUTION_PENDING,
        DISTRIBUTION_IN_PROGRESS, DISTRIBUTION_FAILED,
        ACTIVATION_PENDING, ACTIVATION_IN_PROGRESS,
        ACTIVATION_FAILED, DEVICE_UP_TO_DATE,UNKNOWN.
    type: str
  sortBy:
    description:
      - >
        SortBy query parameter. Sort the response by
        a specified attribute. Available attributes
        for sorting are `id`,`networkDeviceUpdateStatus`,`networkDeviceImageStatus`,
        `goldenImages.name`, `goldenImages.version`,
        `installedImages.name`, `installedImages.version`.
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
      Image Management (SWIM) GetTheListOfNetworkDevicesWithImageDetails
    description: Complete reference of the GetTheListOfNetworkDevicesWithImageDetails
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-the-list-of-network-devices-with-image-details
notes:
  - SDK Method used are
    software_image_management_swim.SoftwareImageManagementSwim.get_the_list_of_network_devices_with_image_details,
  - Paths used are
    get /dna/intent/api/v1/networkDeviceImages,
"""

EXAMPLES = r"""
---
- name: Get all Network Device Images
  cisco.dnac.network_device_images_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    managementAddress: string
    networkDeviceImageStatus: string
    networkDeviceUpdateStatus: string
    sortBy: string
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
        }
      ],
      "version": "string"
    }
"""
