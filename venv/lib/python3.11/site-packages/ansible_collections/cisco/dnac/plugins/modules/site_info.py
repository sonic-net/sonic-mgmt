#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: site_info
short_description: Information module for Site
description:
  - Get all Site.
  - Get sites by site-name-hierarchy or siteId or type.
    List all sites if these parameters are not given
    as an input.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  name:
    description:
      - Name query parameter. Site name hierarchy (E.g
        Global/USA/CA).
    type: str
  siteId:
    description:
      - SiteId query parameter. Site Id.
    type: str
  type:
    description:
      - Type query parameter. Site type (Ex area, building,
        floor).
    type: str
  offset:
    description:
      - Offset query parameter. Offset/starting index
        for pagination. Indexed from 1.
    type: int
  limit:
    description:
      - Limit query parameter. Number of sites to be
        listed.
    type: int
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Sites GetSite
    description: Complete reference of the GetSite API.
    link: https://developer.cisco.com/docs/dna-center/#!get-site
notes:
  - SDK Method used are
    sites.Sites.get_site,
  - Paths used are
    get /dna/intent/api/v1/site,
"""

EXAMPLES = r"""
---
- name: Get all Site
  cisco.dnac.site_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    name: string
    siteId: string
    type: string
    offset: 0
    limit: 0
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: list
  elements: dict
  sample: >
    [
      {
        "parentId": "string",
        "name": "string",
        "additionalInfo": [
          "string"
        ],
        "siteHierarchy": "string",
        "siteNameHierarchy": "string",
        "instanceTenantId": "string",
        "id": "string"
      }
    ]
"""
