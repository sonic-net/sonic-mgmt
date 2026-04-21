#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: qos_device_interface_info
short_description: Information module for Qos Device
  Interface
description:
  - Get all Qos Device Interface.
  - Get all or by network device id, existing qos device
    interface infos.
version_added: '4.0.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  networkDeviceId:
    description:
      - NetworkDeviceId query parameter. Network device
        id.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Application
      Policy GetQosDeviceInterfaceInfo
    description: Complete reference of the GetQosDeviceInterfaceInfo
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-qos-device-interface-info
notes:
  - SDK Method used are
    application_policy.ApplicationPolicy.get_qos_device_interface_info,
  - Paths used are
    get /dna/intent/api/v1/qos-device-interface-info,
"""

EXAMPLES = r"""
---
- name: Get all Qos Device Interface
  cisco.dnac.qos_device_interface_info:
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
          "id": "string",
          "instanceId": 0,
          "displayName": "string",
          "instanceCreatedOn": 0,
          "instanceUpdatedOn": 0,
          "instanceVersion": 0,
          "createTime": 0,
          "deployed": true,
          "isSeeded": true,
          "isStale": true,
          "lastUpdateTime": 0,
          "name": "string",
          "namespace": "string",
          "provisioningState": "string",
          "qualifier": "string",
          "resourceVersion": 0,
          "targetIdList": [
            {}
          ],
          "type": "string",
          "cfsChangeInfo": [
            {}
          ],
          "customProvisions": [
            {}
          ],
          "excludedInterfaces": [
            "string"
          ],
          "isExcluded": true,
          "networkDeviceId": "string",
          "qosDeviceInterfaceInfo": [
            {
              "id": "string",
              "instanceId": 0,
              "displayName": "string",
              "instanceCreatedOn": 0,
              "instanceUpdatedOn": 0,
              "instanceVersion": 0,
              "dmvpnRemoteSitesBw": [
                0
              ],
              "downloadBW": 0,
              "interfaceId": "string",
              "interfaceName": "string",
              "label": "string",
              "role": "string",
              "uploadBW": 0
            }
          ]
        }
      ],
      "version": "string"
    }
"""
