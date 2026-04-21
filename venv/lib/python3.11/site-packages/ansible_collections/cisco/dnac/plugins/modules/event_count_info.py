#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: event_count_info
short_description: Information module for Event Count
description:
  - Get all Event Count.
  - Get the count of registered events with provided
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
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Event Management
      CountOfEvents
    description: Complete reference of the CountOfEvents
      API.
    link: https://developer.cisco.com/docs/dna-center/#!count-of-events
notes:
  - SDK Method used are
    event_management.EventManagement.count_of_events,
  - Paths used are
    get /dna/intent/api/v1/events/count,
"""

EXAMPLES = r"""
---
- name: Get all Event Count
  cisco.dnac.event_count_info:
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
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": 0
    }
"""
