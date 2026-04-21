#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: wired_network_devices_network_device_id_config_features_intended_service_deployments_info
short_description: Information module for Wired Network
  Devices Network Device Id Config Features Intended
  Service Deployments
description:
  - Get all Wired Network Devices Network Device Id
    Config Features Intended Service Deployments.
  - Returns service deployment status based on filter
    criteria.
version_added: '6.18.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  networkDeviceId:
    description:
      - >
        NetworkDeviceId path parameter. Network device
        ID of the wired device to provision. The API
        /intent/api/v1/network-device can be used to
        get the network device ID.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Wired GetServiceDeploymentStatus
    description: Complete reference of the GetServiceDeploymentStatus
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-service-deployment-status
notes:
  - SDK Method used are
    wired.Wired.get_service_deployment_status,
  - Paths used are
    get /dna/intent/api/v1/wired/networkDevices/{networkDeviceId}/configFeatures/intended/serviceDeployments,
"""

EXAMPLES = r"""
---
- name: Get all Wired Network Devices Network Device
    Id Config Features Intended Service Deployments
  cisco.dnac.wired_network_devices_network_device_id_config_features_intended_service_deployments_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    networkDeviceId: string
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
          "activityId": "string",
          "configGroupName": "string",
          "configGroupVersion": 0,
          "status": "string",
          "provisioningDescription": "string",
          "createTime": 0,
          "lastUpdateTime": 0,
          "startTime": 0,
          "endTime": 0,
          "errorCode": "string",
          "failureReason": "string",
          "provisioningCompleted": true
        }
      ],
      "version": "string"
    }
"""
