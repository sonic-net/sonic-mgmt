#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wireless_accesspoint_configuration_summary_info
short_description: Information module for Wireless Accesspoint
  Configuration Summary
description:
  - Get all Wireless Accesspoint Configuration Summary.
    - > Users can query access point configuration information
    for a specific device by using the Ethernet MAC
    address as a 'key' filter. If no key is specified,
    all access point details will be retrieved based
    on the combination of filters provided.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  key:
    description:
      - Key query parameter. The ethernet MAC address
        of Access point.
    type: str
  wlcIpAddress:
    description:
      - WlcIpAddress query parameter. WLC IP Address.
    type: str
  apMode:
    description:
      - >
        ApMode query parameter. AP Mode. Allowed values
        are Local, Bridge, Monitor, FlexConnect, Sniffer,
        Rogue Detector, SE-Connect, Flex+Bridge, Sensor.
    type: str
  apModel:
    description:
      - ApModel query parameter. AP Model.
    type: str
  meshRole:
    description:
      - MeshRole query parameter. Mesh Role. Allowed
        values are RAP or MAP.
    type: str
  provisioned:
    description:
      - Provisioned query parameter. Indicate whether
        AP provisioned or not. Allowed values are True
        or False.
    type: str
  limit:
    description:
      - >
        Limit query parameter. The number of records
        to show for this page. The default is 500 if
        not specified. The maximum allowed limit is
        500.
    type: float
  offset:
    description:
      - Offset query parameter. The first record to
        show for this page; the first record is numbered
        1.
    type: float
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      GetAccessPointConfiguration
    description: Complete reference of the GetAccessPointConfiguration
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-access-point-configuration
notes:
  - SDK Method used are
    wireless.Wireless.get_access_point_configuration,
  - Paths used are
    get /dna/intent/api/v1/wireless/accesspoint-configuration/summary,
"""

EXAMPLES = r"""
---
- name: Get all Wireless Accesspoint Configuration Summary
  cisco.dnac.wireless_accesspoint_configuration_summary_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    key: string
    wlcIpAddress: string
    apMode: string
    apModel: string
    meshRole: string
    provisioned: string
    limit: 0
    offset: 0
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "adminStatus": "string",
      "apHeight": 0,
      "apMode": "string",
      "apName": "string",
      "ethMac": "string",
      "failoverPriority": "string",
      "ledBrightnessLevel": 0,
      "ledStatus": "string",
      "location": "string",
      "macAddress": "string",
      "primaryControllerName": "string",
      "primaryIpAddress": "string",
      "secondaryControllerName": "string",
      "secondaryIpAddress": "string",
      "tertiaryControllerName": "string",
      "tertiaryIpAddress": "string",
      "meshDTOs": [
        {}
      ],
      "model": "string",
      "wlcIpAddress": "string",
      "reachabilityStatus": "string",
      "managementIpAddress": "string",
      "provisioningStatus": "string",
      "radioDTOs": [
        {
          "ifType": 0,
          "ifTypeValue": "string",
          "slotId": 0,
          "macAddress": "string",
          "adminStatus": "string",
          "powerAssignmentMode": "string",
          "powerlevel": 0,
          "channelAssignmentMode": "string",
          "channelNumber": 0,
          "channelWidth": "string",
          "antennaPatternName": "string",
          "antennaAngle": 0,
          "antennaElevAngle": 0,
          "antennaGain": 0,
          "radioRoleAssignment": {},
          "radioBand": {},
          "cleanAirSI": "string",
          "dualRadioMode": "string"
        }
      ]
    }
"""
