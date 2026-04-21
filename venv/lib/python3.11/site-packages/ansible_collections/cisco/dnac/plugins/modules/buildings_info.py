#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: buildings_info
short_description: Information module for Buildings
description:
  - Get Buildings by id.
  - Gets a building in the network hierarchy.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  id:
    description:
      - Id path parameter. Building Id.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Site Design
      GetsABuildingV2
    description: Complete reference of the GetsABuildingV2
      API.
    link: https://developer.cisco.com/docs/dna-center/#!gets-a-building-v-2
notes:
  - SDK Method used are
    site_design.SiteDesign.gets_a_building_v2,
  - Paths used are
    get /dna/intent/api/v2/buildings/{id},
"""

EXAMPLES = r"""
---
- name: Get Buildings by id
  cisco.dnac.buildings_info:
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
        "parentId": "string",
        "name": "string",
        "latitude": 0,
        "longitude": 0,
        "address": "string",
        "country": "string",
        "type": "string",
        "id": "string",
        "nameHierarchy": "string",
        "siteHierarchyId": "string"
      }
    }
"""
