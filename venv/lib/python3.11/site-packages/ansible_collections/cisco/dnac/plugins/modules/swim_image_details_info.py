#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: swim_image_details_info
short_description: Information module for Swim Image
  Details
description:
  - Get all Swim Image Details.
  - Returns software image list based on a filter criteria.
    For example "filterbyName = cat3k%".
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  imageUuid:
    description:
      - ImageUuid query parameter.
    type: str
  name:
    description:
      - Name query parameter.
    type: str
  family:
    description:
      - Family query parameter.
    type: str
  applicationType:
    description:
      - ApplicationType query parameter.
    type: str
  imageIntegrityStatus:
    description:
      - ImageIntegrityStatus query parameter. ImageIntegrityStatus
        - FAILURE, UNKNOWN, VERIFIED.
    type: str
  version:
    description:
      - Version query parameter. Software Image Version.
    type: str
  imageSeries:
    description:
      - ImageSeries query parameter. Image Series.
    type: str
  imageName:
    description:
      - ImageName query parameter. Image Name.
    type: str
  isTaggedGolden:
    description:
      - IsTaggedGolden query parameter. Is Tagged Golden.
    type: bool
  isCCORecommended:
    description:
      - IsCCORecommended query parameter. Is recommended
        from cisco.com.
    type: bool
  isCCOLatest:
    description:
      - IsCCOLatest query parameter. Is latest from
        cisco.com.
    type: bool
  createdTime:
    description:
      - CreatedTime query parameter. Time in milliseconds
        (epoch format).
    type: int
  imageSizeGreaterThan:
    description:
      - ImageSizeGreaterThan query parameter. Size in
        bytes.
    type: int
  imageSizeLesserThan:
    description:
      - ImageSizeLesserThan query parameter. Size in
        bytes.
    type: int
  sortBy:
    description:
      - SortBy query parameter. Sort results by this
        field.
    type: str
  sortOrder:
    description:
      - SortOrder query parameter. Sort order - 'asc'
        or 'des'. Default is asc.
    type: str
  limit:
    description:
      - Limit query parameter.
    type: int
  offset:
    description:
      - Offset query parameter.
    type: int
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Software
      Image Management (SWIM) GetSoftwareImageDetails
    description: Complete reference of the GetSoftwareImageDetails
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-software-image-details
notes:
  - SDK Method used are
    software_image_management_swim.SoftwareImageManagementSwim.get_software_image_details,
  - Paths used are
    get /dna/intent/api/v1/image/importation,
"""

EXAMPLES = r"""
---
- name: Get all Swim Image Details
  cisco.dnac.swim_image_details_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    imageUuid: string
    name: string
    family: string
    applicationType: string
    imageIntegrityStatus: string
    version: string
    imageSeries: string
    imageName: string
    isTaggedGolden: true
    isCCORecommended: true
    isCCOLatest: true
    createdTime: 0
    imageSizeGreaterThan: 0
    imageSizeLesserThan: 0
    sortBy: string
    sortOrder: string
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
          "applicableDevicesForImage": [
            {
              "mdfId": "string",
              "productId": [
                "string"
              ],
              "productName": "string"
            }
          ],
          "applicationType": "string",
          "createdTime": "string",
          "extendedAttributes": {},
          "family": "string",
          "feature": "string",
          "fileServiceId": "string",
          "fileSize": "string",
          "imageIntegrityStatus": "string",
          "imageName": "string",
          "imageSeries": [
            "string"
          ],
          "imageSource": "string",
          "imageType": "string",
          "imageUuid": "string",
          "importSourceType": "string",
          "isTaggedGolden": true,
          "md5Checksum": "string",
          "name": "string",
          "profileInfo": [
            {
              "description": "string",
              "extendedAttributes": {},
              "memory": 0,
              "productType": "string",
              "profileName": "string",
              "shares": 0,
              "vCpu": 0
            }
          ],
          "shaCheckSum": "string",
          "vendor": "string",
          "version": "string"
        }
      ],
      "version": "string"
    }
"""
