#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: floors_floor_id_access_point_positions_bulk_change
short_description: Resource module for Floors Floor
  Id Access Point Positions Bulk Change
description:
  - Manage operation create of the resource Floors Floor
    Id Access Point Positions Bulk Change.
  - Position or reposition the Access Points on the
    map.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  floorId:
    description: FloorId path parameter. Floor Id.
    type: str
  payload:
    description: Floors Floor Id Access Point Positions
      Bulk Change's payload.
    elements: dict
    suboptions:
      id:
        description: Access Point Id.
        type: str
      position:
        description: Floors Floor Id Access Point Positions
          Bulk Change's position.
        suboptions:
          x:
            description: Access Point X coordinate in
              feet.
            type: float
          y:
            description: Access Point Y coordinate in
              feet.
            type: float
          z:
            description: Access Point Z coordinate in
              feet.
            type: float
        type: dict
      radios:
        description: Floors Floor Id Access Point Positions
          Bulk Change's radios.
        elements: dict
        suboptions:
          antenna:
            description: Floors Floor Id Access Point
              Positions Bulk Change's antenna.
            suboptions:
              azimuth:
                description: Angle of the antenna, measured
                  relative to the x axis, clockwise.
                  The azimuth range is from 0 through
                  360.
                type: int
              elevation:
                description: Elevation of the antenna.
                  The elevation range is from -90 through
                  90.
                type: int
              name:
                description: Antenna type for this Access
                  Point. Use `/dna/intent/api/v1/maps/supported-access-points`
                  to find supported Antennas for a particualr
                  Access Point model.
                type: str
            type: dict
          id:
            description: Radio Id.
            type: str
        type: list
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Site Design
      EditTheAccessPointsPositionsV2
    description: Complete reference of the EditTheAccessPointsPositionsV2
      API.
    link: https://developer.cisco.com/docs/dna-center/#!edit-the-access-points-positions-v-2
notes:
  - SDK Method used are
    site_design.SiteDesign.edit_the_access_points_positions_v2,
  - Paths used are
    post /dna/intent/api/v2/floors/{floorId}/accessPointPositions/bulkChange,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.floors_floor_id_access_point_positions_bulk_change:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    floorId: string
    payload:
      - id: string
        position:
          x: 0
          y: 0
          z: 0
        radios:
          - antenna:
              azimuth: 0
              elevation: 0
              name: string
            id: string
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
