#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_port_channels
short_description: Resource module for Sda Port Channels
description:
  - Manage operations create, update and delete of the
    resource Sda Port Channels.
  - Adds port channels based on user input.
  - Deletes a port channel based on id.
  - Deletes port channels based on user input.
  - Updates port channels based on user input.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  connectedDeviceType:
    description: ConnectedDeviceType query parameter.
      Connected device type of the port channel. The
      allowed values are TRUNK, EXTENDED_NODE.
    type: str
  fabricId:
    description: FabricId query parameter. ID of the
      fabric the device is assigned to.
    type: str
  id:
    description: Id path parameter. ID of the port channel.
    type: str
  networkDeviceId:
    description: NetworkDeviceId query parameter. ID
      of the network device.
    type: str
  payload:
    description: Sda Port Channels's payload.
    elements: dict
    suboptions:
      allowedVlanRanges:
        description: Allowed VLAN of the port channel,
          this option is only applicable to TRUNK connectedDeviceType.
          (VLAN must be between 1 and 4094 (Ex 100,200,300-400)
          or 'all'. In cases value not set when connectedDeviceType
          is TRUNK, default value will be 'all').
        type: str
      connectedDeviceType:
        description: Connected device type of the port
          channel.
        type: str
      description:
        description: Description of the port channel.
        type: str
      fabricId:
        description: ID of the fabric the device is
          assigned to.
        type: str
      interfaceNames:
        description: Interface names for this port channel
          (Maximum 16 ports for LACP protocol, Maximum
          8 ports for PAGP and ON protocol).
        elements: str
        type: list
      nativeVlanId:
        description: Native VLAN of the port channel,
          this option is only applicable to TRUNK connectedDeviceType.
          (VLAN must be between 1 and 4094. In cases
          value not set when connectedDeviceType is
          TRUNK, default value will be 1).
        type: int
      networkDeviceId:
        description: ID of the network device.
        type: str
      protocol:
        description: Protocol of the port channel (only
          PAGP is allowed if connectedDeviceType is
          EXTENDED_NODE).
        type: str
    type: list
  portChannelIds:
    description: PortChannelIds query parameter. IDs
      of the port channels to be selectively deleted(Maximum
      number of IDs this parameter could consume is
      10).
    type: str
  portChannelName:
    description: PortChannelName query parameter. Name
      of the port channel.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA AddPortChannels
    description: Complete reference of the AddPortChannels
      API.
    link: https://developer.cisco.com/docs/dna-center/#!add-port-channels
  - name: Cisco DNA Center documentation for SDA DeletePortChannelById
    description: Complete reference of the DeletePortChannelById
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-port-channel-by-id
  - name: Cisco DNA Center documentation for SDA DeletePortChannels
    description: Complete reference of the DeletePortChannels
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-port-channels
  - name: Cisco DNA Center documentation for SDA UpdatePortChannels
    description: Complete reference of the UpdatePortChannels
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-port-channels
notes:
  - SDK Method used are
    sda.Sda.add_port_channels,
    sda.Sda.delete_port_channel_by_id,
    sda.Sda.update_port_channels,
  - Paths used are
    post /dna/intent/api/v1/sda/portChannels,
    delete /dna/intent/api/v1/sda/portChannels,
    delete
    /dna/intent/api/v1/sda/portChannels/{id},
    put /dna/intent/api/v1/sda/portChannels,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.sda_port_channels:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:
      - allowedVlanRanges: string
        connectedDeviceType: string
        description: string
        fabricId: string
        interfaceNames:
          - string
        nativeVlanId: 0
        networkDeviceId: string
        protocol: string
- name: Update all
  cisco.dnac.sda_port_channels:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:
      - allowedVlanRanges: string
        connectedDeviceType: string
        description: string
        fabricId: string
        id: string
        interfaceNames:
          - string
        nativeVlanId: 0
        networkDeviceId: string
        portChannelName: string
        protocol: string
- name: Delete all
  cisco.dnac.sda_port_channels:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    connectedDeviceType: string
    fabricId: string
    networkDeviceId: string
    portChannelIds: string
    portChannelName: string
- name: Delete by id
  cisco.dnac.sda_port_channels:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    id: string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": "string",
        "url": "string"
      },
      "version": "string"
    }
"""
