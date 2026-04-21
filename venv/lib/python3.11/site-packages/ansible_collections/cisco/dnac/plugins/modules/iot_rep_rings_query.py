#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: iot_rep_rings_query
short_description: Resource module for Iot Rep Rings
  Query
description:
  - Manage operation create of the resource Iot Rep
    Rings Query. - > This API returns the list of REP
    rings for the given fields - networkDeviceId Network
    device ID of the REP ring member. In case of successful
    REP ring creation, any of the REP ring member networkDeviceId
    can be provided. In case of failed REP ring creation,
    provide only root node networkDeviceId. The networkDeviceId
    is the instanceUuid attribute in the response of
    API - /dna/intent/api/v1/networkDevice and deploymentMode
    FABRIC/NON_FABRIC .
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  deploymentMode:
    description: Deployment mode of the configured REP
      ring.
    type: str
  limit:
    description: The number of records to show for this
      page.
    type: int
  networkDeviceId:
    description: Network device id of the REP ring member.
      API `/dna/intent/api/v1/networkDevices` can be
      used to get the list of networkDeviceIds of the
      neighbors , `instanceUuid` attribute in the response
      contains networkDeviceId.
    type: str
  offset:
    description: The first record to show for this page;
      the first record is numbered 1.
    type: int
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Industrial
      Configuration RetrievesTheListOfREPRings
    description: Complete reference of the RetrievesTheListOfREPRings
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-the-list-of-rep-rings
notes:
  - SDK Method used are
    industrial_configuration.IndustrialConfiguration.retrieves_the_list_of_r_e_p_rings,
  - Paths used are
    post /dna/intent/api/v1/iot/repRings/query,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.iot_rep_rings_query:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    deploymentMode: string
    limit: 0
    networkDeviceId: string
    offset: 0
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: list
  sample: >
    [
      {
        "response": [
          {
            "id": "string",
            "networkDeviceId": "string",
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
