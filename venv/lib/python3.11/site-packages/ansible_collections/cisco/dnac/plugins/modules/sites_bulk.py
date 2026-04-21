#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sites_bulk
short_description: Resource module for Sites Bulk
description:
  - Manage operation create of the resource Sites Bulk.
    - > Create area/building/floor together in bulk.
    If site already exist, then that will be ignored.
    Sites in the request payload need not to be ordered.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  payload:
    description: Sites Bulk's payload.
    elements: dict
    suboptions:
      address:
        description: Building address. Example 4900
          Marie P. Debartolo Way, Santa Clara, California
          95054, United States.
        type: str
      country:
        description: Country name. Required for building.
        type: str
      floorNumber:
        description: Floor number. Required for floor.
        type: int
      height:
        description: Floor height. Required for floor.
          Example 10.1.
        type: float
      latitude:
        description: Building Latitude. Example 37.403712.
        type: float
      length:
        description: Floor length. Required for floor.
          Example 110.3.
        type: float
      longitude:
        description: Building Longitude. Example -121.971063.
        type: float
      name:
        description: Site name.
        type: str
      parentNameHierarchy:
        description: Parent hierarchical name. Example
          Global/USA/San Jose/Building1.
        type: str
      rfModel:
        description: Floor RF Model. Required for floor.
        type: str
      type:
        description: Type.
        type: str
      unitsOfMeasure:
        description: Floor unit of measure. Required
          for floor.
        type: str
      width:
        description: Floor width. Required for floor.
          Example 100.5.
        type: float
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Site Design
      CreateSites
    description: Complete reference of the CreateSites
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-sites
notes:
  - SDK Method used are
    site_design.SiteDesign.create_sites,
  - Paths used are
    post /dna/intent/api/v1/sites/bulk,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.sites_bulk:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    payload:
      - address: string
        country: string
        floorNumber: 0
        height: 0
        latitude: 0
        length: 0
        longitude: 0
        name: string
        parentNameHierarchy: string
        rfModel: string
        type: string
        unitsOfMeasure: string
        width: 0
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
