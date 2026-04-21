#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: floors_floor_id_planned_access_point_positions_assign_access_point_positions
short_description: Resource module for Floors Floor
  Id Planned Access Point Positions Assign Access Point
  Positions
description:
  - Manage operation create of the resource Floors Floor
    Id Planned Access Point Positions Assign Access
    Point Positions.
  - Assign Planned Access Points to operations ones.
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
      Positions Assign Access Point Positions's payload.
    elements: dict
    suboptions:
      accessPointId:
        description: Operational Access Point Id.
        type: str
      plannedAccessPointId:
        description: Planned Access Point Id.
        type: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Site Design
      AssignPlannedAccessPointsToOperationsOnesV2
    description: Complete reference of the AssignPlannedAccessPointsToOperationsOnesV2
      API.
    link: https://developer.cisco.com/docs/dna-center/#!assign-planned-access-points-to-operations-ones-v-2
notes:
  - SDK Method used are
    site_design.SiteDesign.assign_planned_access_points_to_operations_ones_v2,
  - Paths used are
    post /dna/intent/api/v2/floors/{floorId}/plannedAccessPointPositions/assignAccessPointPositions,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.floors_floor_id_planned_access_point_positions_assign_access_point_positions:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    floorId: string
    payload:
      - accessPointId: string
        plannedAccessPointId: string
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
