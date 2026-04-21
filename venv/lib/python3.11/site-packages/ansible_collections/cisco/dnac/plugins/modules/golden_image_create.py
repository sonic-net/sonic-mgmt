#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: golden_image_create
short_description: Resource module for Golden Image
  Create
description:
  - Manage operation create of the resource Golden Image
    Create.
  - Golden Tag image. Set siteId as -1 for Global site.
version_added: '4.0.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  deviceFamilyIdentifier:
    description: Device Family Identifier e.g. 277696480-283933147,
      277696480.
    type: str
  deviceRole:
    description: Device Role. Permissible Values ALL,
      UNKNOWN, ACCESS, BORDER ROUTER, DISTRIBUTION and
      CORE.
    type: str
  imageId:
    description: ImageId in uuid format.
    type: str
  siteId:
    description: SiteId in uuid format. For Global Site
      "-1" to be used.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Software
      Image Management (SWIM) TagAsGoldenImage
    description: Complete reference of the TagAsGoldenImage
      API.
    link: https://developer.cisco.com/docs/dna-center/#!tag-as-golden-image
notes:
  - SDK Method used are
    software_image_management_swim.SoftwareImageManagementSwim.tag_as_golden_image,
  - Paths used are
    post /dna/intent/api/v1/image/importation/golden,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.golden_image_create:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    deviceFamilyIdentifier: string
    deviceRole: string
    imageId: string
    siteId: string
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
        "url": "string",
        "taskId": "string"
      }
    }
"""
