#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wired_network_devices_network_device_id_config_features_intended_configuration_models_preview_activity_id
short_description: Resource module for Wired Network
  Devices Network Device Id Config Features Intended
  Configuration Models Preview Activity Id
description:
  - Manage operation delete of the resource Wired Network
    Devices Network Device Id Config Features Intended
    Configuration Models Preview Activity Id. - > Deletes
    the configuration model. The API can be used at
    any step to discard/cancel the provision of intended
    features.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  networkDeviceId:
    description: NetworkDeviceId path parameter. Network
      device ID of the wired device to provision. The
      API /intent/api/v1/network-device can be used
      to get the network device ID.
    type: str
  previewActivityId:
    description: PreviewActivityId path parameter. Activity
      id from POST /intent/api/v1/wired/networkDevices/{netwo...
      or /intent/api/v1/wired/networkDevices/{networkDeviceId}/configFeatures/intended/configurationModels/{preview...
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wired DeleteTheConfigurationModel
    description: Complete reference of the DeleteTheConfigurationModel
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-the-configuration-model
notes:
  - SDK Method used are
    wired.Wired.delete_the_configuration_model,
  - Paths used are
    delete /dna/intent/api/v1/wired/networkDevices/{networkDeviceId}/configFeatures/intended/configurationModels/{previewActivityId},
"""

EXAMPLES = r"""
---
- name: Delete by id
  cisco.dnac.wired_network_devices_network_device_id_config_features_intended_configuration_models_preview_activity_id:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    networkDeviceId: string
    previewActivityId: string
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
