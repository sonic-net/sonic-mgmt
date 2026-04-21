#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: iot_rep_rings_query_count
short_description: Resource module for Iot Rep Rings
  Query Count
description:
  - Manage operation create of the resource Iot Rep
    Rings Query Count. - > This API returns the count
    of REP rings for the given fields - networkDeviceId
    Network device ID of the REP ring member. The networkDeviceId
    is the instanceUuid attribute in the response of
    API - /dna/intent/api/v1/networkDevices and deploymentMode
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
  networkDeviceId:
    description: Network device id of the REP ring member.
      API `/dna/intent/api/v1/networkDevices` can be
      used to get the list of networkDeviceIds of the
      neighbors , `instanceUuid` attribute in the response
      contains networkDeviceId.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Industrial
      Configuration RetrievesTheCountOfREPRings
    description: Complete reference of the RetrievesTheCountOfREPRings
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-the-count-of-rep-rings
notes:
  - SDK Method used are
    industrial_configuration.IndustrialConfiguration.retrieves_the_count_of_r_e_p_rings,
  - Paths used are
    post /dna/intent/api/v1/iot/repRings/query/count,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.iot_rep_rings_query_count:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    deploymentMode: string
    networkDeviceId: string
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
            "count": 0
          }
        ],
        "version": 0
      }
    ]
"""
