#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: images_count_info
short_description: Information module for Images Count
description:
  - Get all Images Count.
  - Returns the count of software images for given `siteId`.
    The default value of siteId is global.
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
        for siteId.
    type: str
  productNameOrdinal:
    description:
      - >
        ProductNameOrdinal query parameter. The product
        name ordinal is a unique value for each network
        device product. The productNameOrdinal can be
        obtained from the response of the API `/dna/intent/api/v1/siteWiseProductNames`.
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
        be utilised to download images from Cisco.com
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
        it will retrieve the images marked tagged golden.
        When set to `false`, it will retrieve the images
        marked not tagged golden.
    type: str
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
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Software
      Image Management (SWIM) ReturnsCountOfSoftwareImages
    description: Complete reference of the ReturnsCountOfSoftwareImages
      API.
    link: https://developer.cisco.com/docs/dna-center/#!returns-count-of-software-images
notes:
  - SDK Method used are
    software_image_management_swim.SoftwareImageManagementSwim.returns_count_of_software_images,
  - Paths used are
    get /dna/intent/api/v1/images/count,
"""

EXAMPLES = r"""
---
- name: Get all Images Count
  cisco.dnac.images_count_info:
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
    golden: string
    integrity: string
    hasAddonImages: true
    isAddonImages: true
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
