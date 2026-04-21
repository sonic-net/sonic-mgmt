#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: event_series_count_info
short_description: Information module for Event Series
  Count
description:
  - Get all Event Series Count.
  - Get the Count of Published Notifications.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  eventIds:
    description:
      - EventIds query parameter. The registered EventId
        should be provided.
    type: str
  startTime:
    description:
      - StartTime query parameter. Start Time in milliseconds.
    type: float
  endTime:
    description:
      - EndTime query parameter. End Time in milliseconds.
    type: float
  category:
    description:
      - Category query parameter.
    type: str
  type:
    description:
      - Type query parameter.
    type: str
  severity:
    description:
      - Severity query parameter.
    type: str
  domain:
    description:
      - Domain query parameter.
    type: str
  subDomain:
    description:
      - SubDomain query parameter. Sub Domain.
    type: str
  source:
    description:
      - Source query parameter.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Event Management
      CountOfNotifications
    description: Complete reference of the CountOfNotifications
      API.
    link: https://developer.cisco.com/docs/dna-center/#!count-of-notifications
notes:
  - SDK Method used are
    event_management.EventManagement.count_of_notifications,
  - Paths used are
    get /dna/intent/api/v1/event/event-series/count,
"""

EXAMPLES = r"""
---
- name: Get all Event Series Count
  cisco.dnac.event_series_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    eventIds: string
    startTime: 0
    endTime: 0
    category: string
    type: string
    severity: string
    domain: string
    subDomain: string
    source: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: str
  sample: >
    "string"
"""
