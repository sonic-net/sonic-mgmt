#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wireless_settings_anchor_groups
short_description: Resource module for Wireless Settings
  Anchor Groups
description:
  - Manage operation create of the resource Wireless
    Settings Anchor Groups.
  - This API allows the user to create an AnchorGroup.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  anchorGroupName:
    description: Anchor Group Name. Max length is 32
      characters.
    type: str
  mobilityAnchors:
    description: Wireless Settings Anchor Groups's mobilityAnchors.
    elements: dict
    suboptions:
      anchorPriority:
        description: This indicates anchor priority.
          Priority values range from 1 (high) to 3 (low).
          Primary, secondary or tertiary and defined
          priority is displayed with guest anchor. Only
          one priority value is allowed per anchor WLC.
        type: str
      deviceName:
        description: Peer Host Name.
        type: str
      ipAddress:
        description: This indicates Mobility public
          IP address. Allowed formats are 192.168.0.1,
          10.0.0.1, 255.255.255.255.
        type: str
      macAddress:
        description: Peer Device mobility MAC address.
          Allowed formats are 0a0b.0c01.0211, 0a0b0c010211,
          0a 0b 0c 01 02 11.
        type: str
      managedAnchorWlc:
        description: This indicates whether the Wireless
          LAN Controller supporting Anchor is managed
          by the Network Controller or not. True means
          this is managed by Network Controller.
        type: bool
      mobilityGroupName:
        description: Peer Device mobility group Name.
          Must be alphanumeric without {!,<,space,?/'}
          and maximum of 31 characters.
        type: str
      peerDeviceType:
        description: Indicates peer device mobility
          belongs to AireOS or IOS-XE family.
        type: str
      privateIp:
        description: This indicates private management
          IP address. Allowed formats are 192.168.0.1,
          10.0.0.1, 255.255.255.255.
        type: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      CreateAnchorGroup
    description: Complete reference of the CreateAnchorGroup
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-anchor-group
notes:
  - SDK Method used are
    wireless.Wireless.create_anchor_group,
  - Paths used are
    post /dna/intent/api/v1/wirelessSettings/anchorGroups,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.wireless_settings_anchor_groups:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    anchorGroupName: string
    mobilityAnchors:
      - anchorPriority: string
        deviceName: string
        ipAddress: string
        macAddress: string
        managedAnchorWlc: true
        mobilityGroupName: string
        peerDeviceType: string
        privateIp: string
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
