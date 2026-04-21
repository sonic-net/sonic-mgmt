#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: golden_tag_image_details_info
short_description: Information module for Golden Tag
  Image Details
description:
  - Get Golden Tag Image Details by id.
  - Get golden tag status of an image. Set siteId as
    -1 for Global site.
version_added: '4.0.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  siteId:
    description:
      - SiteId path parameter. Site Id in uuid format.
        Set siteId as -1 for Global site.
    type: str
  deviceFamilyIdentifier:
    description:
      - DeviceFamilyIdentifier path parameter. Device
        family identifier e.g. 277696480-283933147,
        e.g. 277696480.
    type: str
  deviceRole:
    description:
      - >
        DeviceRole path parameter. Device Role. Permissible
        Values ALL, UNKNOWN, ACCESS, BORDER ROUTER,
        DISTRIBUTION and CORE.
    type: str
  imageId:
    description:
      - ImageId path parameter. Image Id in uuid format.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Software
      Image Management (SWIM) GetGoldenTagStatusOfAnImage
    description: Complete reference of the GetGoldenTagStatusOfAnImage
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-golden-tag-status-of-an-image
notes:
  - SDK Method used are
    software_image_management_swim.SoftwareImageManagementSwim.get_golden_tag_status_of_an_image,
  - Paths used are
    get /dna/intent/api/v1/image/importation/golden/site/{siteId}/family/{deviceFamilyIdentifier}/role/{deviceRole}/image/{imageId},
"""

EXAMPLES = r"""
---
- name: Get Golden Tag Image Details by id
  cisco.dnac.golden_tag_image_details_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    siteId: string
    deviceFamilyIdentifier: string
    deviceRole: string
    imageId: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "version": "string",
      "response": {
        "deviceRole": "string",
        "taggedGolden": true,
        "inheritedSiteName": "string",
        "inheritedSiteId": "string"
      }
    }
"""
