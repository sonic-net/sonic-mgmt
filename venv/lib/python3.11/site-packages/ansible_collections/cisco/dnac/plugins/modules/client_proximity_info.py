#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: client_proximity_info
short_description: Information module for Client Proximity
description:
  - Get all Client Proximity. - > This intent API will
    provide client proximity information for a specific
    wireless user. Proximity is defined as presence
    on the same floor at the same time as the specified
    wireless user. The Proximity workflow requires the
    subscription to the following event via the Event
    Notification workflow prior to making this API call
    NETWORK-CLIENTS-3-506 - Client Proximity Report.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  username:
    description:
      - Username query parameter. Wireless client username
        for which proximity information is required.
    type: str
  number_days:
    description:
      - >
        Number_days query parameter. Number of days
        to track proximity until current date. Defaults
        and maximum up to 14 days.
    type: float
  time_resolution:
    description:
      - >
        Time_resolution query parameter. Time interval
        (in minutes) to measure proximity. Defaults
        to 15 minutes with a minimum 5 minutes.
    type: float
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Clients
      ClientProximity
    description: Complete reference of the ClientProximity
      API.
    link: https://developer.cisco.com/docs/dna-center/#!client-proximity
notes:
  - SDK Method used are
    clients.Clients.client_proximity,
  - Paths used are
    get /dna/intent/api/v1/client-proximity,
"""

EXAMPLES = r"""
---
- name: Get all Client Proximity
  cisco.dnac.client_proximity_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    username: string
    number_days: 0
    time_resolution: 0
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "executionId": "string",
      "executionStatusUrl": "string",
      "message": "string"
    }
"""
