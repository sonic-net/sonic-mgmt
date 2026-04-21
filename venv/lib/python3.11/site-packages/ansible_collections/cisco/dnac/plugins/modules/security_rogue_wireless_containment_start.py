#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: security_rogue_wireless_containment_start
short_description: Resource module for Security Rogue
  Wireless-Containment Start
description:
  - Manage operation create of the resource Security
    Rogue Wireless-Containment Start. - > Intent API
    to start the wireless rogue access point containment.
    This API will initiate the containment operation
    on the strongest detecting WLC for the given Rogue
    AP. This is a resource intensive operation which
    has legal implications since the rogue access point
    on whom it is triggered, might be a valid neighbor
    access point.
version_added: '6.16.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  macAddress:
    description: Mac Address.
    type: str
  type:
    description: Type.
    type: int
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      StartWirelessRogueAPContainment
    description: Complete reference of the StartWirelessRogueAPContainment
      API.
    link: https://developer.cisco.com/docs/dna-center/#!start-wireless-rogue-ap-containment
notes:
  - SDK Method used are
    devices.Devices.start_wireless_rogue_ap_containment,
  - Paths used are
    post /dna/intent/api/v1/security/rogue/wireless-containment/start,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.security_rogue_wireless-containment_start:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    macAddress: string
    type: 0
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "macAddress": "string",
        "type": 0,
        "initiatedOnWlcIp": "string",
        "taskId": "string",
        "taskType": "string",
        "initiatedOnBssid": [
          "string"
        ]
      },
      "version": "string"
    }
"""
