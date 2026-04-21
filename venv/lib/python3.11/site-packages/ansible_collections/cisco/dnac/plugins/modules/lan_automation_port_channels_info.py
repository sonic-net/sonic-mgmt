#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: lan_automation_port_channels_info
short_description: Information module for Lan Automation
  Port Channels
description:
  - Get all Lan Automation Port Channels.
  - Returns a list of Port Channel between the LAN Automation
    associated devices.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  device1ManagementIPAddress:
    description:
      - Device1ManagementIPAddress query parameter.
        The management IP address of the device1.
    type: str
  device1Uuid:
    description:
      - Device1Uuid query parameter. Unique identifier
        for the network device1.
    type: str
  device2ManagementIPAddress:
    description:
      - Device2ManagementIPAddress query parameter.
        The management IP address of the device2.
    type: str
  device2Uuid:
    description:
      - Device2Uuid query parameter. Unique identifier
        for the network device2.
    type: str
  offset:
    description:
      - Offset query parameter. Starting record for
        pagination.
    type: str
  limit:
    description:
      - Limit query parameter. Maximum number of Port
        Channel to return.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for LAN Automation
      GetPortChannels
    description: Complete reference of the GetPortChannels
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-port-channels
notes:
  - SDK Method used are
    lan_automation.LanAutomation.get_port_channels,
  - Paths used are
    get /dna/intent/api/v1/lanAutomation/portChannels,
"""

EXAMPLES = r"""
---
- name: Get all Lan Automation Port Channels
  cisco.dnac.lan_automation_port_channels_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    device1ManagementIPAddress: string
    device1Uuid: string
    device2ManagementIPAddress: string
    device2Uuid: string
    offset: string
    limit: string
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
