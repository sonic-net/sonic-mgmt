#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: lan_automation_port_channels_id_info
short_description: Information module for Lan Automation
  Port Channels Id
description:
  - Get Lan Automation Port Channels Id by id.
  - This API retrieves Port Channel information using
    its ID.
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
      - Id path parameter. ID of the port channel.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for LAN Automation
      GetPortChannelInformationById
    description: Complete reference of the GetPortChannelInformationById
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-port-channel-information-by-id
notes:
  - SDK Method used are
    lan_automation.LanAutomation.get_port_channel_information_by_id,
  - Paths used are
    get /dna/intent/api/v1/lanAutomation/portChannels/{id},
"""

EXAMPLES = r"""
---
- name: Get Lan Automation Port Channels Id by id
  cisco.dnac.lan_automation_port_channels_id_info:
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
          "device1ManagementIPAddress": "string",
          "device1Uuid": "string",
          "device2ManagementIPAddress": "string",
          "device2Uuid": "string",
          "device1PortChannelUuid": "string",
          "device1PortChannelNumber": 0,
          "device2PortChannelUuid": "string",
          "device2PortChannelNumber": 0,
          "portChannelMembers": [
            {
              "device1InterfaceUuid": "string",
              "device1Interface": "string",
              "device2InterfaceUuid": "string",
              "device2Interface": "string"
            }
          ]
        }
      ],
      "version": "string"
    }
"""
