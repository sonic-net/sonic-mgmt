#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wired_network_devices_network_device_id_config_features_intended_deploy
short_description: Resource module for Wired Network
  Devices Network Device Id Config Features Intended
  Deploy
description:
  - Manage operation create of the resource Wired Network
    Devices Network Device Id Config Features Intended
    Deploy. - > Deploy the intended configuration features
    on a wired device. This can be used only if the
    provisioning settings do not require Preview or
    ITSM Approval before deploying configurations on
    network devices. The API /intent/api/v1/provisioningSettings
    can be used to get or update provisioning settings.
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
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wired DeployTheIntendedConfigurationFeaturesOnAWiredDevice
    description: Complete reference of the DeployTheIntendedConfigurationFeaturesOnAWiredDevice
      API.
    link: https://developer.cisco.com/docs/dna-center/#!deploy-the-intended-configuration-features-on-a-wired-device
notes:
  - SDK Method used are
    wired.Wired.deploy_the_intended_configuration_features_on_a_wired_device,
  - Paths used are
    post /dna/intent/api/v1/wired/networkDevices/{networkDeviceId}/configFeatures/intended/deploy,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.wired_network_devices_network_device_id_config_features_intended_deploy:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    networkDeviceId: string
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
