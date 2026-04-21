#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: floors_floor_id_planned_access_point_positions_id
short_description: Resource module for Floors Floor
  Id Planned Access Point Positions Id
description:
  - Manage operation delete of the resource Floors Floor
    Id Planned Access Point Positions Id.
  - Delete specified Planned Access Points Position
    designated for a specific floor.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  floorId:
    description: FloorId path parameter. Floor Id.
    type: str
  id:
    description: Id path parameter. Planned Access Point
      Id.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Site Design
      DeletePlannedAccessPointsPositionV2
    description: Complete reference of the DeletePlannedAccessPointsPositionV2
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-planned-access-points-position-v-2
notes:
  - SDK Method used are
    site_design.SiteDesign.delete_planned_access_points_position_v2,
  - Paths used are
    delete /dna/intent/api/v2/floors/{floorId}/plannedAccessPointPositions/{id},
"""

EXAMPLES = r"""
---
- name: Delete by id
  cisco.dnac.floors_floor_id_planned_access_point_positions_id:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    floorId: string
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
