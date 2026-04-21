#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: event_info
short_description: Information module for Event
description:
  - Get all Event.
  - Gets the list of registered Events with provided
    eventIds or tags as mandatory.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  eventId:
    description:
      - EventId query parameter. The registered EventId
        should be provided.
    type: str
  tags:
    description:
      - Tags query parameter. The registered Tags should
        be provided.
    type: str
  offset:
    description:
      - Offset query parameter. The number of Registries
        to offset in the resultset whose default value
        0.
    type: int
  limit:
    description:
      - Limit query parameter. The number of Registries
        to limit in the resultset whose default value
        10.
    type: int
  sortBy:
    description:
      - SortBy query parameter. SortBy field name.
    type: str
  order:
    description:
      - Order query parameter.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Event Management
      GetEvents
    description: Complete reference of the GetEvents
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-events
notes:
  - SDK Method used are
    event_management.EventManagement.get_events,
  - Paths used are
    get /dna/intent/api/v1/events,
"""

EXAMPLES = r"""
---
- name: Get all Event
  cisco.dnac.event_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    eventId: string
    tags: string
    offset: 0
    limit: 0
    sortBy: string
    order: string
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
        "eventId": "string",
        "nameSpace": "string",
        "name": "string",
        "description": "string",
        "version": "string",
        "category": "string",
        "domain": "string",
        "subDomain": "string",
        "type": "string",
        "tags": [
          "string"
        ],
        "severity": 0,
        "details": {},
        "subscriptionTypes": [
          "string"
        ]
      }
    ]
"""
