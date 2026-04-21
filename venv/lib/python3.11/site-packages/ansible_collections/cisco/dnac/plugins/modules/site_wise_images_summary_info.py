#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: site_wise_images_summary_info
short_description: Information module for Site Wise
  Images Summary
description:
  - Get all Site Wise Images Summary. - > Returns aggregate
    counts of network device product names, golden and
    non-golden tagged products, imported images, golden
    images tagged, and advisor for a specific site provide,
    the default value of `siteId` is set to global.
version_added: '6.17.0'
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
        the aggreagte counts products under the site.
        The default value is global site id. See https
        //developer.cisco.com/docs/dna-center(#!get-site)
        for `siteId`.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Software
      Image Management (SWIM) ReturnsTheImageSummaryForTheGivenSite
    description: Complete reference of the ReturnsTheImageSummaryForTheGivenSite
      API.
    link: https://developer.cisco.com/docs/dna-center/#!returns-the-image-summary-for-the-given-site
notes:
  - SDK Method used are
    software_image_management_swim.SoftwareImageManagementSwim.returns_the_image_summary_for_the_given_site,
  - Paths used are
    get /dna/intent/api/v1/siteWiseImagesSummary,
"""

EXAMPLES = r"""
---
- name: Get all Site Wise Images Summary
  cisco.dnac.site_wise_images_summary_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    siteId: string
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
        "importedImageCount": 0,
        "installedImageCount": 0,
        "goldenImageCount": 0,
        "nonGoldenImageCount": 0,
        "installedImageAdvisorCount": 0,
        "productCount": 0,
        "productsWithGoldenCount": 0,
        "productsWithoutGoldenCount": 0
      },
      "version": "string"
    }
"""
