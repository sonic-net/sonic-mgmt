#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: floors_floor_id_planned_access_point_positions_bulk
short_description: Resource module for Floors Floor
  Id Planned Access Point Positions Bulk
description:
  - Manage operation create of the resource Floors Floor
    Id Planned Access Point Positions Bulk.
  - Add Planned Access Points Positions on the map.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  floorId:
    description: FloorId path parameter. Floor Id.
    type: str
  payload:
    description: Floors Floor Id Planned Access Point
      Positions Bulk's payload.
    elements: dict
    suboptions:
      macAddress:
        description: Planned Access Point MAC address.
        type: str
      name:
        description: Planned Access Point Name.
        type: str
      position:
        description: Floors Floor Id Planned Access
          Point Positions Bulk's position.
        suboptions:
          x:
            description: Planned Access Point X coordinate
              in feet.
            type: float
          y:
            description: Planned Access Point Y coordinate
              in feet.
            type: float
          z:
            description: Planned Access Point Z coordinate
              in feet.
            type: float
        type: dict
      radios:
        description: Floors Floor Id Planned Access
          Point Positions Bulk's radios.
        elements: dict
        suboptions:
          antenna:
            description: Floors Floor Id Planned Access
              Point Positions Bulk's antenna.
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
                description: Antenna type for this Planned
                  Access Point. Use `/dna/intent/api/v1/maps/supported-acc...
                  to find supported Antennas for a particualr
                  Planned Access Point type.
                type: str
            type: dict
          bands:
            description: Radio frequencies in GHz. Radio
              frequencies are expected to be 2.4, 5,
              and 6. MinItems 1; MaxItems 3.
            elements: float
            type: list
          channel:
            description: Channel to be used by the Planned
              Access Point. In the context of a Planned
              Access Point, the channel have no bearing
              on what the real Access Point will actually
              be, they are just used for Maps visualization
              feature set.
            type: int
          txPower:
            description: Transmit power for the channel
              in Decibel milliwatts (dBm). In the context
              of a Planned Access Point, the txPower
              have no bearing on what the real Access
              Point will actually be, they are just
              used for Maps visualization feature set.
            type: int
        type: list
      type:
        description: Planned Access Point type. Use
          `dna/intent/api/v1/maps/supported-access-points`
          to find the supported models.
        type: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Site Design
      AddPlannedAccessPointsPositionsV2
    description: Complete reference of the AddPlannedAccessPointsPositionsV2
      API.
    link: https://developer.cisco.com/docs/dna-center/#!add-planned-access-points-positions-v-2
notes:
  - SDK Method used are
    site_design.SiteDesign.add_planned_access_points_positions_v2,
  - Paths used are
    post /dna/intent/api/v2/floors/{floorId}/plannedAccessPointPositions/bulk,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.floors_floor_id_planned_access_point_positions_bulk:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    floorId: string
    payload:
      - macAddress: string
        name: string
        position:
          x: 0
          y: 0
          z: 0
        radios:
          - antenna:
              azimuth: 0
              elevation: 0
              name: string
            bands:
              - 0
            channel: 0
            txPower: 0
        type: string
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
