#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: sda_fabric_border_device_info
short_description: Information module for Sda Fabric
  Border Device
description:
  - Get all Sda Fabric Border Device.
  - Get border device detail from SDA Fabric.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module_info
author: Rafael Campos (@racampos)
options:
  headers:
    description: Additional headers.
    type: dict
  deviceManagementIpAddress:
    version_added: "4.0.0"
    description:
      - DeviceManagementIpAddress query parameter.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for SDA GetBorderDeviceDetailFromSDAFabric
    description: Complete reference of the GetBorderDeviceDetailFromSDAFabric
      API.
    link: https://developer.cisco.com/docs/dna-center/#!get-border-device-detail-from-sda-fabric
notes:
  - SDK Method used are
    sda.Sda.gets_border_device_detail,
  - Paths used are
    get /dna/intent/api/v1/business/sda/border-device,
"""

EXAMPLES = r"""
---
- name: Get all Sda Fabric Border Device
  cisco.dnac.sda_fabric_border_device_info:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    headers: "{{my_headers | from_json}}"
    deviceManagementIpAddress: string
  register: result
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "status": "string",
      "description": "string",
      "payload": {
        "id": "string",
        "instanceId": 0,
        "authEntityId": 0,
        "displayName": "string",
        "authEntityClass": 0,
        "instanceTenantId": "string",
        "deployPending": "string",
        "instanceVersion": 0,
        "createTime": 0,
        "deployed": true,
        "isSeeded": true,
        "isStale": true,
        "lastUpdateTime": 0,
        "name": "string",
        "namespace": "string",
        "provisioningState": "string",
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
        "configs": [
          {}
        ],
        "managedSites": [
          {}
        ],
        "networkDeviceId": "string",
        "roles": [
          "string"
        ],
        "saveWanConnectivityDetailsOnly": true,
        "siteId": "string",
        "akcSettingsCfs": [
          {}
        ],
        "deviceInterfaceInfo": [
          {}
        ],
        "deviceSettings": {
          "id": "string",
          "instanceId": 0,
          "displayName": "string",
          "instanceTenantId": "string",
          "deployPending": "string",
          "instanceVersion": 0,
          "connectedTo": [
            {}
          ],
          "cpu": 0,
          "dhcpEnabled": true,
          "externalConnectivityIpPool": "string",
          "externalDomainRoutingProtocol": "string",
          "internalDomainProtocolNumber": "string",
          "memory": 0,
          "nodeType": [
            "string"
          ],
          "storage": 0,
          "extConnectivitySettings": [
            {
              "id": "string",
              "instanceId": 0,
              "displayName": "string",
              "instanceTenantId": "string",
              "deployPending": "string",
              "instanceVersion": 0,
              "externalDomainProtocolNumber": "string",
              "interfaceUuid": "string",
              "policyPropagationEnabled": true,
              "policySgtTag": 0,
              "l2Handoff": [
                {}
              ],
              "l3Handoff": [
                {
                  "id": "string",
                  "instanceId": 0,
                  "displayName": "string",
                  "instanceTenantId": "string",
                  "deployPending": "string",
                  "instanceVersion": 0,
                  "localIpAddress": "string",
                  "remoteIpAddress": "string",
                  "vlanId": 0,
                  "virtualNetwork": {
                    "idRef": "string"
                  }
                }
              ]
            }
          ]
        },
        "networkWideSettings": {
          "id": "string",
          "instanceId": 0,
          "displayName": "string",
          "instanceTenantId": "string",
          "deployPending": "string",
          "instanceVersion": 0,
          "aaa": [
            {}
          ],
          "cmx": [
            {}
          ],
          "dhcp": [
            {
              "id": "string",
              "ipAddress": {
                "id": "string",
                "paddedAddress": "string",
                "addressType": "string",
                "address": "string"
              }
            }
          ],
          "dns": [
            {
              "id": "string",
              "domainName": "string",
              "ip": {
                "id": "string",
                "paddedAddress": "string",
                "addressType": "string",
                "address": "string"
              }
            }
          ],
          "ldap": [
            {}
          ],
          "nativeVlan": [
            {}
          ],
          "netflow": [
            {}
          ],
          "ntp": [
            {}
          ],
          "snmp": [
            {}
          ],
          "syslogs": [
            {}
          ]
        },
        "otherDevice": [
          {}
        ],
        "transitNetworks": [
          {
            "idRef": "string"
          }
        ],
        "virtualNetwork": [
          {}
        ],
        "wlan": [
          {}
        ]
      }
    }
"""
