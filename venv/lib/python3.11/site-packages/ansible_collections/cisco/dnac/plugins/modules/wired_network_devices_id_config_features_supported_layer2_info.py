#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wired_network_devices_id_config_features_supported_layer2_info
short_description: Information module for Wired Network
  Devices Id Config Features Supported Layer2
description:
  - Get all Wired Network Devices Id Config Features
    Supported Layer2.
  - The API returns the supported layer 2 features on
    a wired device.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  id:
    description:
      - Id path parameter. Network device ID of the
        wired device.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wired GetTheSupportedLayer2FeaturesOnAWiredDevice
    description: Complete reference of the GetTheSupportedLayer2FeaturesOnAWiredDevice
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-the-supported-layer-2-features-on-a-wired-device
notes:
  - SDK Method used are
    wired.Wired.get_the_supported_layer2_features_on_a_wired_device,
  - Paths used are
    get /dna/intent/api/v1/wired/networkDevices/{id}/configFeatures/supported/layer2,
"""

EXAMPLES = r"""
---
- name: Get all Wired Network Devices Id Config Features
    Supported Layer2
  cisco.dnac.wired_network_devices_id_config_features_supported_layer2_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
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
      "response": [
        {
          "name": "string"
        }
      ],
      "version": "string"
    }
"""
