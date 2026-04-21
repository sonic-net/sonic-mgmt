#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: security_rogue_additional_details
short_description: Resource module for Security Rogue
  Additional Details
description:
  - Manage operation create of the resource Security
    Rogue Additional Details. - > This API provides
    additional information of the rogue threats with
    details at BSSID level. The additional information
    includes Switch Port details in case of Rogue on
    Wire, first time when the rogue is seen in the network
    etc.
version_added: '6.16.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  endTime:
    description: This is the epoch end time in milliseconds
      upto which data need to be fetched. Default value
      is current time.
    type: float
  limit:
    description: The maximum number of entries to return.
      Default value is 1000.
    type: float
  offset:
    description: The offset of the first item in the
      collection to return. Default value is 1.
    type: float
  siteId:
    description: Filter Rogues by location. Site IDs
      information can be fetched from "Get Site" API.
    elements: str
    type: list
  startTime:
    description: This is the epoch start time in milliseconds
      from which data need to be fetched. Default value
      is 24 hours earlier to endTime.
    type: float
  threatLevel:
    description: Filter Rogues by Threat Level. Threat
      Level information can be fetched from "Get Threat
      Levels" API.
    elements: str
    type: list
  threatType:
    description: Filter Rogues by Threat Type. Threat
      Type information can be fetched from "Get Threat
      Types" API.
    elements: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Devices
      RogueAdditionalDetails
    description: Complete reference of the RogueAdditionalDetails
      API.
    link: https://developer.cisco.com/docs/dna-center/#!rogue-additional-details
notes:
  - SDK Method used are
    devices.Devices.rogue_additional_details,
  - Paths used are
    post /dna/intent/api/v1/security/rogue/additional/details,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.security_rogue_additional_details:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    endTime: 0
    limit: 0
    offset: 0
    siteId:
      - string
    startTime: 0
    threatLevel:
      - string
    threatType:
      - string
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
          "macAddress": "string",
          "mldMacAddress": "string",
          "updatedTime": 0,
          "createdTime": 0,
          "threatType": "string",
          "threatLevel": "string",
          "apName": "string",
          "detectingAPMac": "string",
          "ssid": "string",
          "containment": "string",
          "radioType": "string",
          "controllerIp": "string",
          "controllerName": "string",
          "channelNumber": "string",
          "siteNameHierarchy": "string",
          "encryption": "string",
          "switchIp": "string",
          "switchName": "string",
          "portDescription": "string"
        }
      ],
      "totalCount": 0,
      "version": "string"
    }
"""
