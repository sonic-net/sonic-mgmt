#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: iot_rep_rings_id_info
short_description: Information module for Iot Rep Rings
  Id
description:
  - Get Iot Rep Rings Id by id. - > This API returns
    REP ring for the given id The id of configured REP
    ring can be retrieved using the API /dna/intent/api/v1/iot/repRings/query
    .
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  id:
    description:
      - >
        Id path parameter. Ring ID of configured REP
        ring can be fetched using the API `/dna/intent/api/v1/iot/repRings/query`.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Industrial
      Configuration GetTheREPRingBasedOnTheRingId
    description: Complete reference of the GetTheREPRingBasedOnTheRingId
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-the-rep-ring-based-on-the-ring-id
notes:
  - SDK Method used are
    industrial_configuration.IndustrialConfiguration.get_the_r_e_p_ring_based_on_the_ring_id,
  - Paths used are
    get /dna/intent/api/v1/iot/repRings/{id},
"""

EXAMPLES = r"""
---
- name: Get Iot Rep Rings Id by id
  cisco.dnac.iot_rep_rings_id_info:
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
  type: list
  elements: dict
  sample: >
    [
      {
        "response": [
          {
            "id": "string",
            "rootNetworkDeviceId": "string",
            "rootNeighbourNetworkDeviceIds": [
              "string"
            ],
            "status": "string",
            "repSegmentId": 0,
            "deploymentMode": "string",
            "ringName": "string",
            "ringMembers": [
              {
                "networkDeviceId": "string",
                "nodeName": "string",
                "portName1": "string",
                "portName2": "string",
                "ringOrder": 0
              }
            ]
          }
        ],
        "version": 0
      }
    ]
"""
