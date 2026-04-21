#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wired_network_devices_id_config_features_intended_layer2_feature_count_info
short_description: Information module for Wired Network
  Devices Id Config Features Intended Layer2 Feature
  Count
description:
  - Get Wired Network Devices Id Config Features Intended
    Layer2 Feature Count by id.
  - This API returns the count of the instances of the
    configurations for an intended layer 2 feature on
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
        wired device to configure.
    type: str
  feature:
    description:
      - >
        Feature path parameter. Name of the feature
        to configure. The API /dna/intent/api/v1/networkDevices/{id}/configFeatures/supported/layer2
        can be used to get the list of features supported
        on a device.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wired GetNumberOfConfigurationsForAnIntendedLayer2FeatureOnAWiredDevice
    description: Complete reference of the GetNumberOfConfigurationsForAnIntendedLayer2FeatureOnAWiredDevice
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-number-of-configurations-for-an-intended-layer-2-feature-on-a-wired-device
notes:
  - SDK Method used are
    wired.Wired.get_number_of_configurations_for_an_intended_layer2_feature_on_a_wired_device,
  - Paths used are
    get /dna/intent/api/v1/wired/networkDevices/{id}/configFeatures/intended/layer2/{feature}/count,
"""

EXAMPLES = r"""
---
- name: Get Wired Network Devices Id Config Features
    Intended Layer2 Feature Count by id
  cisco.dnac.wired_network_devices_id_config_features_intended_layer2_feature_count_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    id: string
    feature: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": 0,
      "version": "string"
    }
"""
