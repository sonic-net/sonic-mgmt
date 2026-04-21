#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: site_update
short_description: Resource module for Site Update
description:
  - Manage operation update of the resource Site Update.
  - Update site area/building/floor with specified hierarchy
    and new values.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  site:
    description: Site Update's site.
    suboptions:
      area:
        description: Site Update's area.
        suboptions:
          name:
            description: Area name.
            type: str
          parentName:
            description: Parent hierarchical name (Example
              Global/USA/CA).
            type: str
        type: dict
      building:
        description: Site Update's building.
        suboptions:
          address:
            description: Building address (Example 4900
              Marie P. Debartolo Way, Santa Clara, California
              95054, United States).
            type: str
          country:
            description: Country name. This field is
              mandatory for air-gapped networks (Example
              United States).
            type: str
          latitude:
            description: Building latitude (Example
              37.403712).
            type: float
          longitude:
            description: Building longitude (Example
              -121.971063).
            type: float
          name:
            description: Building name.
            type: str
          parentName:
            description: Parent hierarchical name (Example
              Global/USA/CA/SantaClara).
            type: str
        type: dict
      floor:
        description: Site Update's floor.
        suboptions:
          floorNumber:
            description: Floor Number (Example 3).
            type: float
          height:
            description: Floor height in feet (Example
              10).
            type: float
          length:
            description: Floor length in feet (Example
              100).
            type: float
          name:
            description: Floor name.
            type: str
          parentName:
            description: Parent hierarchical name (Example
              Global/USA/CA/SantaClara/Academic).
            type: str
          rfModel:
            description: RF model (Example Cubes And
              Walled Offices).
            type: str
          width:
            description: Floor width in feet (Example
              200).
            type: float
        type: dict
    type: dict
  siteId:
    description: SiteId path parameter. Site id to which
      site details to be updated.
    type: str
  type:
    description: Site type.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Sites UpdateSite
    description: Complete reference of the UpdateSite
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-site
notes:
  - SDK Method used are
    sites.Sites.update_site,
  - Paths used are
    put /dna/intent/api/v1/site/{siteId},
"""

EXAMPLES = r"""
---
- name: Update by id
  cisco.dnac.site_update:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: '{{my_headers | from_json}}'
    site:
      area:
        name: string
        parentName: string
      building:
        address: string
        country: string
        latitude: 0
        longitude: 0
        name: string
        parentName: string
      floor:
        floorNumber: 0
        height: 0
        length: 0
        name: string
        parentName: string
        rfModel: string
        width: 0
    siteId: string
    type: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "result": "string",
      "response": {
        "endTime": "string",
        "version": "string",
        "startTime": "string",
        "progress": "string",
        "data": "string",
        "serviceType": "string",
        "operationIdList": [
          "string"
        ],
        "isError": "string",
        "rootId": "string",
        "instanceTenantId": "string",
        "id": "string"
      },
      "status": "string"
    }
"""
