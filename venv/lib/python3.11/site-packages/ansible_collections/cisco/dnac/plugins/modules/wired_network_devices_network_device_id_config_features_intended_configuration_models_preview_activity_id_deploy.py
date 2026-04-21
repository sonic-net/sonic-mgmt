#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wired_network_devices_network_device_id_config_features_intended_configuration_models_preview_activity_id_deploy
short_description: Resource module for Wired Network
  Devices Network Device Id Config Features Intended
  Configuration Models Preview Activity Id Deploy
description:
  - Manage operation create of the resource Wired Network
    Devices Network Device Id Config Features Intended
    Configuration Models Preview Activity Id Deploy.
    - > This API deploys the configuration model on
    the network device. This is the final step 'Step
    4' of the following workflow. Step 1- Use 'POST
    /intent/api/v1/wired/networkDevices/{networkDeviceId}/configFeatures/intended/configurationModels'
    to start the provision of intended features. The
    response has a taskId which is the previewActivityId
    in all subsequent APIs. The task must be successfully
    complete before proceeding to the next step. It
    is not recommended to proceed when there is any
    task failure in this step. The API 'DELETE /intent/api/v1/wired/networkDevices/{netw
    orkDeviceId}/configFeatures/intended/configurationModels/{previewActivityId}'
    can be used at any step to discard/cancel the provision
    of intended features. Step 2- Use 'POST /intent/api/v1/wired/networkDevices/{netw
    orkDeviceId}/configFeatures/intended/configurationModels/{previewActivityId}/networkDevices/{networkDeviceId}/
    config' to generate device CLIs for preview. The
    response has a task ID. The task must be successfully
    complete before using the GET API to view CLIs.
    It is not recommended to proceed when there is any
    task failures in this step. The API 'DELETE /intent/api/v1/wired/networkDevices/{networkDeviceId}/configFeatures/in
    tended/configurationModels/{previewActivityId}'
    can be used at any step to discard/cancel the provision
    of intended features. Step 3- Use 'GET /intent/api/v1/wired/networkDevices/{networkDeviceId}/configFeatures/inten
    ded/configurationModels/{previewActivityId}/networkDevices/{networkDeviceId}/config'
    to view the CLIs that will be applied to the device.
    Step 4- Use 'POST /intent/api/v1/wired/networkDevices/{networkDeviceId}/configF
    eatures/intended/configurationModels/{previewActivityId}/deploy'
    to push the intent to the device.
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
      id from intent/api/v1/activity.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wired DeployTheConfigurationModelOnTheNetworkDevice
    description: Complete reference of the DeployTheConfigurationModelOnTheNetworkDevice
      API.
    link: https://developer.cisco.com/docs/dna-center/#!deploy-the-configuration-model-on-the-network-device
notes:
  - SDK Method used are
    wired.Wired.deploy_the_configuration_model_on_the_network_device,
  - Paths used are
    post /dna/intent/api/v1/intent/api/v1/wired/networkDevices/{networkDeviceId}/configFeatures/intended/configurationModels/{previewActivityId}/deploy,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.wired_network_devices_network_device_id_config_features_intended_configuration_models_preview_activity_id_deploy:
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
