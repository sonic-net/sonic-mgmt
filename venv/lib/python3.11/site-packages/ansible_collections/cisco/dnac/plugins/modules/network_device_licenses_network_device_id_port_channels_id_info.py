#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: network_device_licenses_network_device_id_port_channels_id_info
short_description: Information module for Network Device
  Licenses Network Device Id Port Channels Id
description:
  - Get Network Device Licenses Network Device Id Port
    Channels Id by id. - > This API endpoint retrieves
    detailed information for a specified port channel
    using its unique identifier within a given network
    device.
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
      - Id path parameter. Unique identifier for the
        port channel.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      RetrievesInformationForTheGivenPortChannelOnASpecificNetworkDevice
    description: Complete reference of the RetrievesInformationForTheGivenPortChannelOnASpecificNetworkDevice
      API.
    link: https://developer.cisco.com/docs/dna-center/#!retrieves-information-for-the-given-port-channel-on-a-specific-network-device
notes:
  - SDK Method used are
    devices.Devices.retrieves_information_for_the_given_port_channel_on_a_specific_network_device,
  - Paths used are
    get /dna/intent/api/v1/networkDevices/{networkDeviceId}/portChannels/{id},
"""

EXAMPLES = r"""
---
- name: Get Network Device Licenses Network Device Id
    Port Channels Id by id
  cisco.dnac.network_device_licenses_network_device_id_port_channels_id_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    networkDeviceId: string
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
      "response": {
        "id": "string",
        "name": "string",
        "aggregationProtocol": "string",
        "logicalSlotPort": "string",
        "interfaces": {
          "name": "string",
          "channelMode": "string"
        },
        "networkDeviceId": "string"
      },
      "version": "string"
    }
"""
