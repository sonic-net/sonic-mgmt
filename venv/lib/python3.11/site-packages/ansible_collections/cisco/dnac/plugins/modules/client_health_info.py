#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: client_health_info
short_description: Information module for Client Health
description:
  - Get all Client Health.
  - Returns Overall Client Health information by Client
    type Wired and Wireless for any given point of time.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  timestamp:
    description:
      - Timestamp query parameter. Epoch time(in milliseconds)
        when the Client health data is required.
    type: float
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Clients
      GetOverallClientHealth
    description: Complete reference of the GetOverallClientHealth
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-overall-client-health
notes:
  - SDK Method used are
    clients.Clients.get_overall_client_health,
  - Paths used are
    get /dna/intent/api/v1/client-health,
"""

EXAMPLES = r"""
---
- name: Get all Client Health
  cisco.dnac.client_health_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    timestamp: 0
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "version": "string",
      "response": [
        {
          "siteId": "string",
          "scoreDetail": [
            {
              "scoreCategory": {
                "scoreCategory": "string",
                "value": "string"
              },
              "scoreValue": 0,
              "clientCount": 0,
              "clientUniqueCount": 0,
              "maintenanceAffectedClientCount": 0,
              "randomMacCount": 0,
              "duidCount": 0,
              "starttime": 0,
              "endtime": 0,
              "connectedToUdnCount": 0,
              "unconnectedToUdnCount": 0,
              "scoreList": [
                {
                  "scoreCategory": {
                    "scoreCategory": "string",
                    "value": "string"
                  },
                  "scoreValue": 0,
                  "clientCount": 0,
                  "clientUniqueCount": 0,
                  "maintenanceAffectedClientCount": 0,
                  "randomMacCount": 0,
                  "duidCount": 0,
                  "starttime": 0,
                  "endtime": 0,
                  "connectedToUdnCount": 0,
                  "unconnectedToUdnCount": 0
                }
              ]
            }
          ]
        }
      ]
    }
"""
