#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_pending_fabric_events_info
short_description: Information module for Sda Pending
  Fabric Events
description:
  - Get all Sda Pending Fabric Events.
  - Returns a list of pending fabric events that match
    the provided query parameters.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  fabricId:
    description:
      - FabricId query parameter. ID of the fabric.
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
  - name: Cisco DNA Center documentation for SDA GetPendingFabricEvents
    description: Complete reference of the GetPendingFabricEvents
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-pending-fabric-events
notes:
  - SDK Method used are
    sda.Sda.get_pending_fabric_events,
  - Paths used are
    get /dna/intent/api/v1/sda/pendingFabricEvents,
"""

EXAMPLES = r"""
---
- name: Get all Sda Pending Fabric Events
  cisco.dnac.sda_pending_fabric_events_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    fabricId: string
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
          "fabricId": "string",
          "detail": "string"
        }
      ],
      "version": "string"
    }
"""
