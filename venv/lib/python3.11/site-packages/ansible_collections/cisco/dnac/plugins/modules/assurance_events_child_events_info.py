#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: assurance_events_child_events_info
short_description: Information module for Assurance
  Events Child Events
description:
  - Get all Assurance Events Child Events. - > Wireless
    client event could have child events and this API
    can be used to fetch the same using parent event
    `id` as the input. For detailed information about
    the usage of the API, please refer to the Open API
    specification document - https //github.com/cisco-en-programmability/catalyst-center-api-
    specs/blob/main/Assurance/CE_Cat_Center_Org-AssuranceEvents-1.0.0-resolved.yaml.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  id:
    description:
      - Id path parameter. Unique identifier for the
        event.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      GetListOfChildEventsForTheGivenWirelessClientEvent
    description: Complete reference of the GetListOfChildEventsForTheGivenWirelessClientEvent
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-list-of-child-events-for-the-given-wireless-client-event
notes:
  - SDK Method used are
    devices.Devices.get_list_of_child_events_for_the_given_wireless_client_event,
  - Paths used are
    get /dna/data/api/v1/assuranceEvents/{id}/childEvents,
"""

EXAMPLES = r"""
---
- name: Get all Assurance Events Child Events
  cisco.dnac.assurance_events_child_events_info:
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
  type: dict
  sample: >
    {
      "response": [
        {
          "id": "string",
          "name": "string",
          "timestamp": 0,
          "wirelessEventType": 0,
          "details": "string",
          "reasonCode": "string",
          "subreasonCode": "string",
          "resultStatus": "string",
          "reasonDescription": "string",
          "subReasonDescription": "string",
          "failureCategory": "string"
        }
      ],
      "version": "string"
    }
"""
