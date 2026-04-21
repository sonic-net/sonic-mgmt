#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_port_channels_count_info
short_description: Information module for Sda Port Channels
  Count
description:
  - Get all Sda Port Channels Count.
  - Returns the count of port channels that match the
    provided query parameters.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  fabricId:
    description:
      - FabricId query parameter. ID of the fabric the
        device is assigned to.
    type: str
  networkDeviceId:
    description:
      - NetworkDeviceId query parameter. ID of the network
        device.
    type: str
  portChannelName:
    description:
      - PortChannelName query parameter. Name of the
        port channel.
    type: str
  connectedDeviceType:
    description:
      - >
        ConnectedDeviceType query parameter. Connected
        device type of the port channel. The allowed
        values are TRUNK, EXTENDED_NODE.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA GetPortChannelCount
    description: Complete reference of the GetPortChannelCount
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-port-channel-count
notes:
  - SDK Method used are
    sda.Sda.get_port_channel_count,
  - Paths used are
    get /dna/intent/api/v1/sda/portChannels/count,
"""

EXAMPLES = r"""
---
- name: Get all Sda Port Channels Count
  cisco.dnac.sda_port_channels_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    fabricId: string
    networkDeviceId: string
    portChannelName: string
    connectedDeviceType: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "count": 0
      },
      "version": "string"
    }
"""
