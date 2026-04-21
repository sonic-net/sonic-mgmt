#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: update_wired_network_devices_id_config_features_intended_layer2
short_description: Resource module for Update Wired
  Network Devices Id Config Features Intended Layer2
description:
  - Manage operation update of the resource Update Wired
    Network Devices Id Config Features Intended Layer2.
    - > This API updates the configurations for the
    intended features on a wired device. Only the feature
    configurations to be changed need to be added to
    the intended features. Updates to intended features
    can be done over several iterations. Once the updates
    are complete, the intended features can be deployed
    to a device using the API /dna/intent/api/v1/networkDevices/{id}/configFeatures/intended/deploy.
    When the intended features are deployed, they are
    applied on top of the existing configurations on
    the device. Any existing configurations on the device
    which are not included in the intended features,
    are retained on the device.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  id:
    description: Id path parameter. Network device ID
      of the wired device to configure.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wired UpdateConfigurationsForIntendedLayer2FeaturesOnAWiredDevice
    description: Complete reference of the UpdateConfigurationsForIntendedLayer2FeaturesOnAWiredDevice
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-configurations-for-intended-layer-2-features-on-a-wired-device
notes:
  - SDK Method used are
    wired.Wired.update_configurations_for_intended_layer2_features_on_a_wired_device,
  - Paths used are
    put /dna/intent/api/v1/wired/networkDevices/{id}/configFeatures/intended/layer2,
"""

EXAMPLES = r"""
---
- name: Update all
  cisco.dnac.update_wired_network_devices_id_config_features_intended_layer2:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
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
