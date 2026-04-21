#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_licenses_network_device_id_port_channels_count_info
short_description: Information module for Network Device
  Licenses Network Device Id Port Channels Count
description:
  - Get all Network Device Licenses Network Device Id
    Port Channels Count.
  - This API endpoint retrieves the count of port channels
    for the given network device.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  networkDeviceId:
    description:
      - NetworkDeviceId path parameter. Unique identifier
        for the network device.
    type: str
  id:
    description:
      - Id query parameter. Optional list of the port
        channel ids to filter by.
    type: str
  name:
    description:
      - >
        Name query parameter. Optional name of the port
        channel to filter by. This supports partial
        search. For example, searching for "Port" will
        match "Port-channel1", "Port-channel2", etc.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      RetrievePortChannelsCountForANetworkDevice
    description: Complete reference of the RetrievePortChannelsCountForANetworkDevice
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieve-port-channels-count-for-a-network-device
notes:
  - SDK Method used are
    devices.Devices.retrieve_port_channels_count_for_a_network_device,
  - Paths used are
    get /dna/intent/api/v1/networkDevices/{networkDeviceId}/portChannels/count,
"""

EXAMPLES = r"""
---
- name: Get all Network Device Licenses Network Device
    Id Port Channels Count
  cisco.dnac.network_device_licenses_network_device_id_port_channels_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    id: string
    name: string
    networkDeviceId: string
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
