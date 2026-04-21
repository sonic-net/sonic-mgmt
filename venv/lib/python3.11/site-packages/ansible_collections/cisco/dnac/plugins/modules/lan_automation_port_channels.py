#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: lan_automation_port_channels
short_description: Resource module for Lan Automation
  Port Channels
description:
  - Manage operation create of the resource Lan Automation
    Port Channels. - > This API creates a Port Channel
    between two LAN Automation associated devices using
    the PAgP protocol, with a minimum of 2 and a maximum
    of 8 LAN Automated interfaces in UP status.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  device1ManagementIPAddress:
    description: Either device1ManagementIPAddress or
      device1Uuid is required.
    type: str
  device1Uuid:
    description: Either device1ManagementIPAddress or
      device1Uuid is required.
    type: str
  device2ManagementIPAddress:
    description: Either device2ManagementIPAddress or
      device2Uuid is required.
    type: str
  device2Uuid:
    description: Either device2ManagementIPAddress or
      device2Uuid is required.
    type: str
  portChannelMembers:
    description: Lan Automation Port Channels's portChannelMembers.
    elements: dict
    suboptions:
      device1Interface:
        description: Either device1InterfaceUuid or
          device1InterfaceName is required.
        type: str
      device1InterfaceUuid:
        description: Either device1InterfaceUuid or
          device1InterfaceName is required.
        type: str
      device2Interface:
        description: Either device2InterfaceUuid or
          device2InterfaceName is required.
        type: str
      device2InterfaceUuid:
        description: Either device2InterfaceUuid or
          device2InterfaceName is required.
        type: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for LAN Automation
      CreateANewPortChannelBetweenDevices
    description: Complete reference of the CreateANewPortChannelBetweenDevices
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-a-new-port-channel-between-devices
notes:
  - SDK Method used are
    lan_automation.LanAutomation.create_a_new_port_channel_between_devices,
  - Paths used are
    post /dna/intent/api/v1/lanAutomation/portChannels,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.lan_automation_port_channels:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    device1ManagementIPAddress: string
    device1Uuid: string
    device2ManagementIPAddress: string
    device2Uuid: string
    portChannelMembers:
      - device1Interface: string
        device1InterfaceUuid: string
        device2Interface: string
        device2InterfaceUuid: string
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
