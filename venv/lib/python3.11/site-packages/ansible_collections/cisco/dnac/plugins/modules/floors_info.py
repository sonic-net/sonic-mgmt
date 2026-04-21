#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: floors_info
short_description: Information module for Floors
description:
  - Get Floors by id.
  - Gets a floor in the network hierarchy.
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
      - Id path parameter. Floor Id.
    type: str
  _unitsOfMeasure:
    description:
      - _unitsOfMeasure query parameter. Floor units
        of measure.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Site Design
      GetsAFloorV2
    description: Complete reference of the GetsAFloorV2
      API.
    link: https://developer.cisco.com/docs/dna-center/#!gets-a-floor-v-2
notes:
  - SDK Method used are
    site_design.SiteDesign.gets_a_floor_v2,
  - Paths used are
    get /dna/intent/api/v2/floors/{id},
"""

EXAMPLES = r"""
---
- name: Get Floors by id
  cisco.dnac.floors_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    _unitsOfMeasure: string
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
        "floorNumber": 0,
        "rfModel": "string",
        "width": 0,
        "length": 0,
        "height": 0,
        "unitsOfMeasure": "string",
        "type": "string",
        "id": "string",
        "nameHierarchy": "string",
        "siteHierarchyId": "string"
      }
    }
"""
