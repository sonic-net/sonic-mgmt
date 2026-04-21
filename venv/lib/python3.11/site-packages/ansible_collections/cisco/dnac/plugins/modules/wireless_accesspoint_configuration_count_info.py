#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wireless_accesspoint_configuration_count_info
short_description: Information module for Wireless Accesspoint
  Configuration Count
description:
  - Get all Wireless Accesspoint Configuration Count.
  - Get Access Point Configuration Count.
version_added: '6.17.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
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
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wireless
      GetAccessPointConfigurationCount
    description: Complete reference of the GetAccessPointConfigurationCount
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-access-point-configuration-count
notes:
  - SDK Method used are
    wireless.Wireless.get_access_point_configuration_count,
  - Paths used are
    get /dna/intent/api/v1/wireless/accesspoint-configuration/count,
"""

EXAMPLES = r"""
---
- name: Get all Wireless Accesspoint Configuration Count
  cisco.dnac.wireless_accesspoint_configuration_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    wlcIpAddress: string
    apMode: string
    apModel: string
    meshRole: string
    provisioned: string
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
