#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: floors_floor_id_planned_access_point_positions_count_info
short_description: Information module for Floors Floor
  Id Planned Access Point Positions Count
description:
  - Get all Floors Floor Id Planned Access Point Positions
    Count.
  - Retrieve all Planned Access Points Positions count
    designated for a specific floor.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  floorId:
    description:
      - FloorId path parameter. Floor Id.
    type: str
  name:
    description:
      - Name query parameter. Planned Access Point name.
    type: str
  macAddress:
    description:
      - MacAddress query parameter. Planned Access Point
        mac address.
    type: str
  type:
    description:
      - Type query parameter. Planned Access Point type.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Site Design
      GetPlannedAccessPointsPositionsCountV2
    description: Complete reference of the GetPlannedAccessPointsPositionsCountV2
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-planned-access-points-positions-count-v-2
notes:
  - SDK Method used are
    site_design.SiteDesign.get_planned_access_points_positions_count_v2,
  - Paths used are
    get /dna/intent/api/v2/floors/{floorId}/plannedAccessPointPositions/count,
"""

EXAMPLES = r"""
---
- name: Get all Floors Floor Id Planned Access Point
    Positions Count
  cisco.dnac.floors_floor_id_planned_access_point_positions_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    name: string
    macAddress: string
    type: string
    floorId: string
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
        "count": 0
      },
      "version": "string"
    }
"""
