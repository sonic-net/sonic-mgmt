#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sites_info
short_description: Information module for Sites
description:
  - Get all Sites.
  - Get sites.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  name:
    description:
      - Name query parameter. Site name.
    type: str
  nameHierarchy:
    description:
      - NameHierarchy query parameter. Site name hierarchy.
    type: str
  type:
    description:
      - Type query parameter. Site type.
    type: str
  _unitsOfMeasure:
    description:
      - _unitsOfMeasure query parameter. Floor units
        of measure.
    type: str
  offset:
    description:
      - Offset query parameter. The first record to
        show for this page; the first record is numbered
        1.
    type: float
  limit:
    description:
      - Limit query parameter. The number of records
        to show for this page;The minimum is 1, and
        the maximum is 500.
    type: float
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Site Design
      GetSites
    description: Complete reference of the GetSites
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-sites
notes:
  - SDK Method used are
    site_design.SiteDesign.get_sites,
  - Paths used are
    get /dna/intent/api/v1/sites,
"""

EXAMPLES = r"""
---
- name: Get all Sites
  cisco.dnac.sites_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    name: string
    nameHierarchy: string
    type: string
    _unitsOfMeasure: string
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
          "nameHierarchy": "string",
          "name": "string",
          "latitude": 0,
          "longitude": 0,
          "address": "string",
          "country": "string",
          "floorNumber": 0,
          "rfModel": "string",
          "width": 0,
          "length": 0,
          "height": 0,
          "unitsOfMeasure": "string",
          "type": "string",
          "id": "string",
          "parentId": "string",
          "siteHierarchyId": "string"
        }
      ],
      "version": "string"
    }
"""
