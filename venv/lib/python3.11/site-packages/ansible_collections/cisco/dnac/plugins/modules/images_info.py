#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: images_info
short_description: Information module for Images
description:
  - Get all Images. - > A list of available images for
    the specified site is provided. The default value
    of the site is set to global. The list includes
    images that have been imported onto the disk, as
    well as the latest and suggested images from Cisco.com.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  siteId:
    description:
      - >
        SiteId query parameter. Site identifier to get
        the list of all available products under the
        site. The default value is the global site.
        See https //developer.cisco.com/docs/dna-center/get-site
        for `siteId`.
    type: str
  productNameOrdinal:
    description:
      - >
        ProductNameOrdinal query parameter. The product
        name ordinal is a unique value for each network
        device product. The productNameOrdinal can be
        obtained from the response of API `/dna/intent/api/v1/siteWiseProductNames`.
    type: float
  supervisorProductNameOrdinal:
    description:
      - >
        SupervisorProductNameOrdinal query parameter.
        The supervisor engine module ordinal is a unique
        value for each supervisor module. The `supervisorProductNameOrdinal`
        can be obtained from the response of API `/dna/intent/api/v1/siteWiseProductNames`.
    type: float
  imported:
    description:
      - >
        Imported query parameter. When the value is
        set to `true`, it will include physically imported
        images. Conversely, when the value is set to
        `false`, it will include image records from
        the cloud. The identifier for cloud images can
        be utilized to download images from Cisco.com
        to the disk.
    type: bool
  name:
    description:
      - >
        Name query parameter. Filter with software image
        or add-on name. Supports partial case-insensitive
        search. A minimum of 3 characters is required
        for the search.
    type: str
  version:
    description:
      - >
        Version query parameter. Filter with image version.
        Supports partial case-insensitive search. A
        minimum of 3 characters is required for the
        search.
    type: str
  golden:
    description:
      - >
        Golden query parameter. When set to `true`,
        it will retrieve the images marked as tagged
        golden. When set to `false`, it will retrieve
        the images marked as not tagged golden.
    type: bool
  integrity:
    description:
      - >
        Integrity query parameter. Filter with verified
        images using Integrity Verification Available
        values UNKNOWN, VERIFIED.
    type: str
  hasAddonImages:
    description:
      - >
        HasAddonImages query parameter. When set to `true`,
        it will retrieve the images which have add-on
        images. When set to `false`, it will retrieve
        the images which do not have add-on images.
    type: bool
  isAddonImages:
    description:
      - >
        IsAddonImages query parameter. When set to `true`,
        it will retrieve the images that an add-on image.
        When set to `false`, it will retrieve the images
        that are not add-on images.
    type: bool
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
      Image Management (SWIM) ReturnsListOfSoftwareImages
    description: Complete reference of the ReturnsListOfSoftwareImages
      API.
    link: https://developer.cisco.com/docs/dna-center/#!returns-list-of-software-images
notes:
  - SDK Method used are
    software_image_management_swim.SoftwareImageManagementSwim.returns_list_of_software_images,
  - Paths used are
    get /dna/intent/api/v1/images,
"""

EXAMPLES = r"""
---
- name: Get all Images
  cisco.dnac.images_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    siteId: string
    productNameOrdinal: 0
    supervisorProductNameOrdinal: 0
    imported: true
    name: string
    version: string
    golden: true
    integrity: string
    hasAddonImages: true
    isAddonImages: true
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
          "imported": true,
          "name": "string",
          "version": "string",
          "imageType": "string",
          "recommended": "string",
          "ciscoLatest": true,
          "integrityStatus": "string",
          "isAddonImage": true,
          "hasAddonImages": true,
          "goldenTaggingDetails": [
            {
              "deviceRoles": [
                "string"
              ],
              "deviceTags": [
                "string"
              ],
              "inheritedSiteId": "string",
              "inheritedSiteName": "string"
            }
          ],
          "productNames": [
            {
              "id": "string",
              "productName": "string",
              "productNameOrdinal": 0,
              "supervisorProductName": "string",
              "supervisorProductNameOrdinal": 0
            }
          ],
          "isGoldenTagged": true
        }
      ],
      "version": "string"
    }
"""
