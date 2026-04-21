#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_fabric_zones_info
short_description: Information module for Sda Fabric
  Zones
description:
  - Get all Sda Fabric Zones.
  - Returns a list of fabric zones that match the provided
    query parameters.
version_added: '6.14.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  id:
    description:
      - Id query parameter. ID of the fabric zone.
    type: str
  siteId:
    description:
      - SiteId query parameter. ID of the network hierarchy
        associated with the fabric zone.
    type: str
  offset:
    description:
      - Offset query parameter. Starting record for
        pagination.
    type: int
  limit:
    description:
      - >
        Limit query parameter. Maximum number of records
        to return. The maximum number of objects supported
        in a single request is 500.
    type: int
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA GetFabricZones
    description: Complete reference of the GetFabricZones
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-fabric-zones
notes:
  - SDK Method used are
    sda.Sda.get_fabric_zones,
  - Paths used are
    get /dna/intent/api/v1/sda/fabricZones,
"""

EXAMPLES = r"""
---
- name: Get all Sda Fabric Zones
  cisco.dnac.sda_fabric_zones_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    id: string
    siteId: string
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
          "id": "string",
          "siteId": "string",
          "authenticationProfileName": "string"
        }
      ],
      "version": "string"
    }
"""
